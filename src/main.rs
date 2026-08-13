//! euvd-cli — terminal UI for the ENISA EU Vulnerability Database.

mod api;
mod app;
mod ui;

use std::io;
use std::time::Duration;

use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event};

use app::App;

fn main() -> io::Result<()> {
    let mut terminal = ratatui::init();
    let result = run(&mut terminal, App::new());
    ratatui::restore();
    result
}

fn run(terminal: &mut DefaultTerminal, mut app: App) -> io::Result<()> {
    app.init();
    while !app.quit {
        terminal.draw(|frame| ui::draw(frame, &mut app))?;
        // Apply any finished background fetches before waiting for input.
        while let Ok(msg) = app.rx.try_recv() {
            app.on_fetched(msg);
        }
        if event::poll(Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(key) => app.on_key(key),
                Event::Resize(..) => {}
                _ => {}
            }
        }
        app.tick = app.tick.wrapping_add(1);
    }
    Ok(())
}
