use args::Args;

mod args;

fn main() {
    let args: Args = argh::from_env();
    println!("{args:#?}");
}
