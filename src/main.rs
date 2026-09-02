mod app;
mod cloud;
mod keystore;
mod reader;
mod ui;

use ui::gui::SacApp;

fn main() {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1200.0, 800.0]),
        ..Default::default()
    };

    let result = eframe::run_native(
        "SAC Client",
        options,
        Box::new(|_cc| Ok(Box::<SacApp>::default())),
    );

    if let Err(err) = result {
        eprintln!("Failed to start GUI: {}", err);
    }
}
