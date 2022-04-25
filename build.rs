#[cfg(not(feature = "performance-counter"))]
fn main() {}

#[cfg(feature = "performance-counter")]
fn main() {
    performance_counter::main();
}

#[cfg(feature = "performance-counter")]
mod performance_counter {

    use serde::{Deserialize, Serialize};
    use serde_json;
    use std::collections::HashMap;
    use std::env;
    use std::fs::File;
    use std::io::{BufReader, BufWriter, Write};
    use std::path::Path;

    #[cfg(feature = "performance-counter")]
    #[serde(rename_all = "lowercase")]
    #[derive(Serialize, Deserialize, Debug)]
    struct PerfCounter {
        eventname: String,
        eventcode: String, // One or two u8/u64-values
        umask: String,      // One or two u8/u64-values
        briefdescription: String,
        publicdescription: String,
        counter: u64,
        counterhtoff: Option<u64>,
        pebscounters: Option<u64>,
        sampleafter_value: u64,
        msrindex: String, // Vec<u64>: len(1) => MSRIndex::One(split_parts[0]), len(2) => MSRIndex::Two(split_parts[0], split_parts[1])
        msrvalue: u64,
        takenalone: bool,
        countermask: u8, //or u8
        invert: bool,
        any_thread: bool,
        edgedetect: bool,
        pebs: u8,
        precisestore: bool,
        data_la: bool,
        l1_hit_indication: bool,
        errata: String,
        offcore: bool,
        unit: String,
        filter: String,
        xxt_sel: bool,
        collect_pebsrecord: Option<u64>,
        ellc: String,
        even_status: u64,
        pdir_counter: String,
        deprecated: bool,
        fcmask: u8,
        filter_value: u64,
        port_mask: u8,
        umask_ext: u8,
        counter_type: String,
    }

    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/perfcnt/intel/description.rs"
    ));

    /// We need to convert parsed strings to static because we're reusing
    /// the struct definition which declare strings as static in the generated
    /// code.
    fn str_to_static_str(s: &str) -> &'static str {
        Box::leak(String::from(s).into_boxed_str())
    }

    fn string_to_static_str(s: &String) -> &'static str {
        Box::leak(s.clone().into_boxed_str())
    }

    fn parse_bool(input: &str) -> bool {
        match input.trim() {
            "0" => false,
            "1" => true,
            _ => panic!("Unknown boolean value {}", input),
        }
    }

    fn parse_hex_numbers(split_str_parts: Vec<&str>) -> Vec<u64> {
        split_str_parts
            .iter()
            .map(|x| {
                assert!(x.starts_with("0x"));
                match u64::from_str_radix(&x[2..], 16) {
                    Ok(u) => u,
                    Err(e) => panic!("{}: Can not parse {}", e, x),
                }
            })
            .collect()
    }

    fn parse_number(value_str: &str) -> u64 {
        if value_str.len() > 2 && value_str[..2].starts_with("0x") {
            match u64::from_str_radix(&value_str[2..], 16) {
                Ok(u) => u,
                Err(e) => panic!("{}: Can not parse {}", e, value_str),
            }
        } else {
            match u64::from_str_radix(&value_str, 10) {
                Ok(u) => u,
                Err(e) => panic!("{}: Can not parse {}", e, value_str),
            }
        }
    }

    fn parse_counter_values(value_str: &str) -> u64 {
        value_str
            .split(',')
            .map(|x| x.trim())
            .filter(|x| !x.is_empty())
            .map(|x| match u64::from_str_radix(&x, 10) {
                Ok(u) => u,
                Err(e) => panic!("{}: Can not parse {} in {}", e, x, value_str),
            })
            .fold(0, |acc, c| acc | 1 << c)
    }

    fn parse_null_string(value_str: &str) -> Option<&str> {
        if value_str != "null" {
            Some(value_str)
        } else {
            None
        }
    }

    fn parse_counters(value_str: &str) -> Counter {
        if value_str.to_lowercase().starts_with("fixed counter") {
            let mask: u64 = parse_counter_values(&value_str["fixed counter".len()..]);
            assert!(mask <= u8::max_value() as u64);
            Counter::Fixed(mask as u8)
        } else if value_str.to_lowercase().starts_with("fixed") {
            let mask: u64 = parse_counter_values(&value_str["fixed".len()..]);
            assert!(mask <= u8::max_value() as u64);
            Counter::Fixed(mask as u8)
        } else {
            let mask: u64 = parse_counter_values(value_str);
            assert!(
                mask <= u8::max_value() as u64,
                "assertion didn't work: {:?} is bigger than u8",
                mask
            );
            Counter::Programmable(mask as u8)
        }
    }

    fn parse_pebs(value_str: &str) -> PebsType {
        match value_str.trim() {
            "0" => PebsType::Regular,
            "1" => PebsType::PebsOrRegular,
            "2" => PebsType::PebsOnly,
            _ => panic!("Unknown PEBS type: {}", value_str),
        }
    }

    fn parse_performance_counters(inputs: Vec<String>, variable: &str, file: &mut BufWriter<File>) {
        let mut builder_values = HashMap::new();
        //let mut all_events = HashMap::new();
        let mut builder = phf_codegen::Map::new();

        for input in inputs {
            println!("input = {}", input);

            let f = File::open(format!("x86data/perfmon_data{}", input.clone()).as_str()).unwrap();
            let reader = BufReader::new(f);
            let data: Vec<PerfCounter> = serde_json::from_reader(reader).unwrap();
            let uncore = get_file_suffix(input.clone()) == "uncore";

            for entry in data.iter() {

                println!("{:?}", entry);
                /* if pcn.do_insert {
                    builder_values.insert(String::from(ipcd.event_name), format!("{:?}", ipcd));
                } */
            }
        }

        write!(
            file,
            "pub const {}: phf::Map<&'static str, EventDescription<'static>> = ",
            variable
        )
        .unwrap();

        for (key, val) in builder_values.iter() {
            // entry needs &'static str so we leak a bunch of Strings
            builder.entry(string_to_static_str(key), string_to_static_str(val));
        }
        writeln!(file, "{};", builder.build()).unwrap();
        file.flush().ok();
    }

    fn make_file_name<'a>(path: &'a Path) -> (String, String) {
        let stem = path.file_stem().unwrap().to_str().unwrap();

        // File name without _core*.json
        println!("{:?}", path);
        let mut core_start = stem.find("_core");
        if core_start.is_none() {
            core_start = stem.find("_uncore");
        }
        assert!(!core_start.is_none());
        let (output_file, _) = stem.split_at(core_start.unwrap());

        // File name without _V*.json at the end:
        let (variable, _) = stem.split_at(core_start.unwrap());
        let uppercase = variable.to_ascii_uppercase();
        let variable_clean = uppercase.replace("-", "_");
        let variable_upper = variable_clean.as_str();

        (output_file.to_string(), variable_upper.to_string())
    }

    pub fn get_file_suffix(file_name: String) -> &'static str {
        if file_name.contains("_core_") {
            "core"
        } else if file_name.contains("_uncore_") {
            "uncore"
        } else if file_name.contains("_matrix_") {
            "matrix"
        } else if file_name.contains("_FP_ARITH_INST_") || file_name.contains("_fp_arith_inst_") {
            "fparith"
        } else {
            panic!("Unknown suffix {}", file_name);
        }
    }

    pub fn main() {
        //println!("cargo:rerun-if-changed=build.rs");
        //println!("cargo:rerun-if-changed=x86data/perfmon_data");

        // First, parse mapfile.csv to find out all supported architectures and their event description locations
        let mut rdr = csv::Reader::from_path("./x86data/perfmon_data/mapfile.csv").unwrap();
        let mut data_files = HashMap::new();

        for record in rdr.records().map(|v| v.unwrap()) {
            let family_model = record.get(0).unwrap().to_string();
            let version = record.get(1).unwrap().to_string();
            let file_name = record.get(2).unwrap().to_string();
            let event_type = record.get(3).unwrap().to_string();
            // TODO: Parse offcore counter descriptions.

            let suffix = get_file_suffix(file_name.clone());
            if suffix == "core" || suffix == "uncore" {
                if !data_files.contains_key(&file_name) {
                    data_files.insert(file_name.clone(), vec![(family_model, version, event_type)]);
                } else {
                    data_files.get_mut(&file_name).unwrap().push((
                        family_model,
                        version,
                        event_type,
                    ));
                }
            }
        }

        // Now build hash-table so we can later select performance counters for each architecture
        let path = Path::new(&env::var("OUT_DIR").unwrap()).join("counters.rs");
        let mut filewriter = BufWriter::new(File::create(&path).unwrap());

        let mut builder = phf_codegen::Map::new();
        let mut inserted: HashMap<String, bool> = HashMap::new();
        for (file, values) in &data_files {
            let path = Path::new(file.as_str());
            let (_, ref variable_upper) = make_file_name(&path);
            for data in values {
                let (ref family_model, _, _): (String, String, String) = *data;
                if !inserted.contains_key(&family_model.to_string()) {
                    // Hashes things like this: GenuineIntel-6-25 -> WESTMERE_EP_SP
                    builder.entry(family_model.as_str(), variable_upper.as_str());
                    inserted.insert(family_model.clone(), true);
                } else {
                    // ignore
                }
            }
        }

        // Next, we write this hash-table (COUNTER_MAP) into our generated rust code file:
        writeln!(
            &mut filewriter,
            "pub static COUNTER_MAP: phf::Map<&'static str, phf::Map<&'static str, \
             EventDescription<'static>>> = {};",
            builder.build()
        )
        .unwrap();

        // Now, parse all JSON files with event data for each architecture and generate hash-tables
        let mut architectures: HashMap<String, Vec<String>> = HashMap::new();
        for file in data_files.keys() {
            let path = Path::new(file.as_str());
            let (_, ref variable_upper) = make_file_name(&path);

            println!("Adding {}", variable_upper);
            architectures
                .entry(variable_upper.to_string())
                .or_insert_with(Vec::new)
                .push(file.clone());
        }

        for (ref arch, ref files) in architectures {
            println!("Processing {:?} {:?}", arch, files);
            parse_performance_counters(files.to_vec(), arch, &mut filewriter);
        }
    }
}
