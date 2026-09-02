use std::sync::mpsc::{self, Receiver};

use eframe::egui;
use tokio::runtime::Runtime;

use crate::{
    app::{download::download_file, upload::upload_file},
    cloud::cloud_factory::build_cloud,
    cloud::provider::{CloudEntry, CloudEntryKind},
    keystore::keystore_factory::build_keystore,
};

enum UiMessage {
    Status(String),
    ListLoaded(Vec<CloudEntry>),
    StatusAndRefresh(String),
}

pub struct SacApp {
    current_dir: String,
    entries: Vec<CloudEntry>,

    new_dir_name: String,

    selected_path: Option<String>,
    selected_kind: Option<CloudEntryKind>,

    status: String,
    busy: bool,
    first_frame: bool,
    rx: Option<Receiver<UiMessage>>,
}

impl Default for SacApp {
    fn default() -> Self {
        Self {
            current_dir: String::new(),
            entries: Vec::new(),
            new_dir_name: String::new(),
            selected_path: None,
            selected_kind: None,
            status: "Ready".to_string(),
            busy: false,
            first_frame: true,
            rx: None,
        }
    }
}

impl SacApp {
    fn start_task<F>(&mut self, task: F)
    where
        F: FnOnce() -> UiMessage + Send + 'static,
    {
        if self.busy {
            return;
        }

        let (tx, rx) = mpsc::channel();

        self.busy = true;
        self.status = "Running...".to_string();
        self.rx = Some(rx);

        std::thread::spawn(move || {
            let message = task();
            let _ = tx.send(message);
        });
    }

    fn poll_task(&mut self) {
        if let Some(rx) = &self.rx {
            if let Ok(message) = rx.try_recv() {
                self.busy = false;
                self.rx = None;

                match message {
                    UiMessage::Status(status) => {
                        self.status = status;
                    }

                    UiMessage::ListLoaded(entries) => {
                        self.entries = entries;
                        self.status = "File list updated".to_string();
                    }

                    UiMessage::StatusAndRefresh(status) => {
                        self.status = status;
                        self.refresh_list();
                    }
                }
            }
        }
    }

    fn clear_selection(&mut self) {
        self.selected_path = None;
        self.selected_kind = None;
    }

    fn selected_is_file(&self) -> bool {
        matches!(self.selected_kind, Some(CloudEntryKind::File))
    }

    fn selected_is_directory(&self) -> bool {
        matches!(self.selected_kind, Some(CloudEntryKind::Directory))
    }

    fn refresh_list(&mut self) {
        let current_dir = self.current_dir.clone();

        self.start_task(move || {
            let rt = Runtime::new().unwrap();

            let cloud = match build_cloud() {
                Ok(service) => service,
                Err(e) => return UiMessage::Status(format!("Cloud config failed: {}", e)),
            };

            match rt.block_on(cloud.ls(&current_dir)) {
                Ok(entries) => UiMessage::ListLoaded(entries),
                Err(e) => UiMessage::Status(format!("List failed: {}", e)),
            }
        });
    }

    fn go_up(&mut self) {
        if self.current_dir.is_empty() {
            return;
        }

        if let Some(pos) = self.current_dir.rfind('/') {
            self.current_dir = self.current_dir[..pos].to_string();
        } else {
            self.current_dir.clear();
        }

        self.clear_selection();
        self.refresh_list();
    }

    fn open_directory(&mut self, path: String) {
        self.current_dir = path;
        self.clear_selection();
        self.refresh_list();
    }

    fn upload_here(&mut self) {
        let Some(path) = rfd::FileDialog::new().pick_file() else {
            return;
        };

        let Some(filename) = path.file_name() else {
            self.status = "Invalid input file".to_string();
            return;
        };

        let filename = filename.to_string_lossy().to_string();

        let remote_path = if self.current_dir.is_empty() {
            filename
        } else {
            format!("{}/{}", self.current_dir, filename)
        };

        let input_path = path.display().to_string();

        self.start_task(move || {
            let rt = Runtime::new().unwrap();

            let cloud = match build_cloud() {
                Ok(service) => service,
                Err(e) => return UiMessage::Status(format!("Cloud config failed: {}", e)),
            };

            let key_service = match build_keystore() {
                Ok(service) => service,
                Err(e) => return UiMessage::Status(format!("Keystore config failed: {}", e)),
            };

            match rt.block_on(upload_file(
                cloud.as_ref(),
                key_service.as_ref(),
                &input_path,
                &remote_path,
            )) {
                Ok(_) => UiMessage::StatusAndRefresh(format!("Uploaded: {}", remote_path)),
                Err(e) => UiMessage::Status(format!("Upload failed: {}", e)),
            }
        });
    }

    fn download_selected_file(&mut self) {
        let Some(remote_path) = self.selected_path.clone() else {
            return;
        };

        let Some(output_path) = rfd::FileDialog::new().save_file() else {
            return;
        };

        let output_path = output_path.display().to_string();

        self.start_task(move || {
            let rt = Runtime::new().unwrap();

            let cloud = match build_cloud() {
                Ok(service) => service,
                Err(e) => return UiMessage::Status(format!("Cloud config failed: {}", e)),
            };

            let key_service = match build_keystore() {
                Ok(service) => service,
                Err(e) => return UiMessage::Status(format!("Keystore config failed: {}", e)),
            };

            match rt.block_on(download_file(
                cloud.as_ref(),
                key_service.as_ref(),
                &remote_path,
                &output_path,
            )) {
                Ok(_) => UiMessage::Status(format!("Downloaded: {}", output_path)),
                Err(e) => UiMessage::Status(format!("Download failed: {}", e)),
            }
        });
    }

    fn delete_selected_file(&mut self) {
        let Some(remote_path) = self.selected_path.clone() else {
            return;
        };

        self.clear_selection();

        self.start_task(move || {
            let rt = Runtime::new().unwrap();

            let cloud = match build_cloud() {
                Ok(service) => service,
                Err(e) => return UiMessage::Status(format!("Cloud config failed: {}", e)),
            };

            match rt.block_on(cloud.delete_encrypted_file(&remote_path)) {
                Ok(_) => UiMessage::StatusAndRefresh(format!("Deleted: {}", remote_path)),
                Err(e) => UiMessage::Status(format!("Delete failed: {}", e)),
            }
        });
    }

    fn create_directory(&mut self) {
        let name = self.new_dir_name.trim().to_string();

        if name.is_empty() {
            self.status = "Directory name is empty".to_string();
            return;
        }

        let path = if self.current_dir.is_empty() {
            name.clone()
        } else {
            format!("{}/{}", self.current_dir, name)
        };

        self.new_dir_name.clear();

        self.start_task(move || {
            let rt = Runtime::new().unwrap();

            let cloud = match build_cloud() {
                Ok(service) => service,
                Err(e) => return UiMessage::Status(format!("Cloud config failed: {}", e)),
            };

            match rt.block_on(cloud.create_dir(&path)) {
                Ok(_) => UiMessage::StatusAndRefresh(format!("Directory created: {}", path)),
                Err(e) => UiMessage::Status(format!("Create directory failed: {}", e)),
            }
        });
    }

    fn delete_selected_directory(&mut self) {
        let Some(path) = self.selected_path.clone() else {
            return;
        };

        if !self.selected_is_directory() {
            return;
        }

        self.clear_selection();

        self.start_task(move || {
            let rt = Runtime::new().unwrap();

            let cloud = match build_cloud() {
                Ok(service) => service,
                Err(e) => return UiMessage::Status(format!("Cloud config failed: {}", e)),
            };

            match rt.block_on(cloud.delete_dir(&path)) {
                Ok(_) => UiMessage::StatusAndRefresh(format!("Directory deleted: {}", path)),
                Err(e) => UiMessage::Status(format!("Delete directory failed: {}", e)),
            }
        });
    }

    fn draw_top_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.add_space(6.0);

            ui.horizontal(|ui| {
                ui.heading("SAC");

                ui.separator();

                if ui
                    .add_enabled(
                        !self.busy && !self.current_dir.is_empty(),
                        egui::Button::new("⬆ Up"),
                    )
                    .clicked()
                {
                    self.go_up();
                }

                if ui
                    .add_enabled(!self.busy, egui::Button::new("🔄 Refresh"))
                    .clicked()
                {
                    self.refresh_list();
                }

                ui.separator();

                ui.label("Path:");
                ui.monospace(format!("/{}", self.current_dir));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.busy {
                        ui.spinner();
                    }
                });
            });

            ui.add_space(6.0);
        });
    }

    fn draw_side_panel(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("side_panel")
            .resizable(false)
            .default_width(260.0)
            .show(ctx, |ui| {
                ui.heading("Actions");
                ui.separator();

                if ui
                    .add_enabled(!self.busy, egui::Button::new("📤 Upload file"))
                    .clicked()
                {
                    self.upload_here();
                }

                ui.add_space(8.0);

                if ui
                    .add_enabled(
                        !self.busy && self.selected_is_file(),
                        egui::Button::new("📥 Download file"),
                    )
                    .clicked()
                {
                    self.download_selected_file();
                }

                if ui
                    .add_enabled(
                        !self.busy && self.selected_path.is_some(),
                        egui::Button::new("🗑 Delete selected"),
                    )
                    .clicked()
                {
                    if self.selected_is_file() {
                        self.delete_selected_file();
                    } else if self.selected_is_directory() {
                        self.delete_selected_directory();
                    }
                }

                ui.add_space(16.0);
                ui.separator();

                ui.heading("New folder");
                ui.text_edit_singleline(&mut self.new_dir_name);

                if ui
                    .add_enabled(!self.busy, egui::Button::new("📁 Create folder"))
                    .clicked()
                {
                    self.create_directory();
                }

                ui.add_space(16.0);
                ui.separator();

                ui.heading("Selected");

                match (&self.selected_path, &self.selected_kind) {
                    (Some(path), Some(kind)) => {
                        let kind_label = match kind {
                            CloudEntryKind::File => "File",
                            CloudEntryKind::Directory => "Directory",
                        };

                        ui.label(kind_label);
                        ui.monospace(path);

                        if matches!(kind, CloudEntryKind::Directory) {
                            ui.add_space(8.0);
                            ui.label("Double click to open.");
                        }
                    }
                    _ => {
                        ui.label("No item selected.");
                    }
                }
            });
    }

    fn draw_file_list(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Files");
            ui.separator();

            if self.entries.is_empty() {
                ui.add_space(20.0);
                ui.vertical_centered(|ui| {
                    ui.label("This folder is empty.");
                });
                return;
            }

            egui::ScrollArea::vertical().show(ui, |ui| {
                for entry in self.entries.clone() {
                    let selected = self.selected_path.as_ref() == Some(&entry.path);

                    let icon = match entry.kind {
                        CloudEntryKind::Directory => "📁",
                        CloudEntryKind::File => "📄",
                    };

                    let label = format!("{} {}", icon, entry.name);

                    let response = ui.add_sized(
                        [ui.available_width(), 28.0],
                        egui::SelectableLabel::new(selected, label),
                    );

                    if response.double_clicked() {
                        if matches!(entry.kind, CloudEntryKind::Directory) {
                            self.open_directory(entry.path.clone());
                        }
                    } else if response.clicked() {
                        self.selected_path = Some(entry.path.clone());
                        self.selected_kind = Some(entry.kind.clone());
                    }
                }
            });
        });
    }

    fn draw_status_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                ui.label("Status:");
                ui.monospace(&self.status);
            });

            ui.add_space(4.0);
        });
    }
}

impl eframe::App for SacApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_task();

        if self.first_frame {
            self.first_frame = false;
            self.refresh_list();
        }

        self.draw_top_bar(ctx);
        self.draw_side_panel(ctx);
        self.draw_status_bar(ctx);
        self.draw_file_list(ctx);

        ctx.request_repaint();
    }
}