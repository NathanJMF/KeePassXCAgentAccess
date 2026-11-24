"""Render a document in the private offline browser and return fixed form facts."""

from contextlib import contextmanager
import json
import os
from select import select
import subprocess
import sys

import gi


gi.require_version("Gtk", "3.0")
gi.require_version("WebKit2", "4.1")


FORM_SCRIPT = """
(config) => {
    const elementsWithId = id => document.querySelectorAll('#' + CSS.escape(id));
    if (config.success_id) return elementsWithId(config.success_id).length === 1;

    const forms = elementsWithId(config.form_id);
    if (forms.length !== 1 || !(forms[0] instanceof HTMLFormElement)) return null;
    const form = forms[0];
    if (form.method !== "post" || form.enctype !== "application/x-www-form-urlencoded") return null;
    let username = false, password = false;
    const extras = new Map();
    const names = new Set();
    for (const control of form.elements) {
        if (!form.contains(control)) return null;
        if (control.hasAttribute("formaction") || control.hasAttribute("formmethod")
            || control.hasAttribute("formenctype")) return null;
        if (!control.name || control.matches(':disabled') ||
            ['submit', 'button', 'reset', 'image'].includes(control.type)) continue;
        if (!(control instanceof HTMLInputElement) || control.name.length > 80
            || control.value.length > 1024) return null;
        if (control.name === config.username_field) {
            if (!['text', 'email'].includes(control.type) || names.has(control.name) || names.size >= 18) return null;
            names.add(control.name);
            username = true;
        } else if (control.name === config.password_field) {
            if (control.type !== 'password' || names.has(control.name) || names.size >= 18) return null;
            names.add(control.name);
            password = true;
        } else if (control.type === 'hidden' || control.type === 'checkbox') {
            if (!names.has(control.name)) {
                if (names.size >= 18) return null;
                names.add(control.name);
            }
            const entry = extras.get(control.name) || {};
            if (control.type in entry) return null;
            entry[control.type] = control.type === 'checkbox'
                ? {checked: control.checked, value: control.value}
                : control.value;
            extras.set(control.name, entry);
        } else {
            return null;
        }
    }
    const hidden = [];
    for (const [name, entry] of extras.entries()) {
        if ('checkbox' in entry && entry.checkbox.checked) {
            hidden.push([name, entry.checkbox.value]);
        } else if ('hidden' in entry) {
            hidden.push([name, entry.hidden]);
        }
    }
    return username && password ? {action: form.action, hidden} : null;
}
"""


@contextmanager
def display():
    read_fd, write_fd = os.pipe()
    try:
        server = subprocess.Popen(
            ["/usr/bin/Xvfb", "-displayfd", str(write_fd), "-nolisten", "tcp",
             "-screen", "0", "640x480x24", "-noreset", "-extension", "GLX"],
            pass_fds=(write_fd,), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        )
    finally:
        os.close(write_fd)
    try:
        if not select([read_fd], [], [], 3)[0]:
            raise TimeoutError
        number = os.read(read_fd, 16).strip()
        if not number.isdigit():
            raise ValueError
        os.environ["DISPLAY"] = ":" + number.decode("ascii")
        yield
    finally:
        os.close(read_fd)
        server.terminate()
        server.wait(timeout=2)


def inspect(document, url, config):
    from gi.repository import GLib, Gtk, WebKit2

    context = WebKit2.WebContext.new_ephemeral()
    view = WebKit2.WebView.new_with_context(context)
    settings = view.get_settings()
    settings.set_enable_javascript_markup(False)
    settings.set_enable_developer_extras(False)
    settings.set_auto_load_images(False)
    window = Gtk.OffscreenWindow()
    window.add(view)
    window.show_all()
    result = None
    loop = GLib.MainLoop()

    def finished(source, reply):
        nonlocal result
        try:
            value = source.evaluate_javascript_finish(reply).to_string()
            if value and len(value) <= 8192:
                result = json.loads(value)
        except (GLib.Error, ValueError):
            pass
        finally:
            loop.quit()

    def loaded(source, event):
        if event == WebKit2.LoadEvent.FINISHED:
            source.evaluate_javascript(
                f"JSON.stringify(({FORM_SCRIPT})({json.dumps(config)}))",
                -1, "keeper-form-inspection", None, None, finished,
            )

    GLib.timeout_add(4500, loop.quit)
    view.connect("load-changed", loaded)
    view.load_html(
        '<!doctype html><meta http-equiv="Content-Security-Policy" '
        'content="default-src \'none\'; form-action \'none\'">' + document,
        url,
    )
    loop.run()
    window.destroy()
    return result


def main():
    reply = os.dup(sys.stdout.fileno())
    try:
        with open(os.devnull, "wb") as sink:
            os.dup2(sink.fileno(), sys.stdout.fileno())
        with display():
            os.write(reply, b"1")
            request = json.loads(sys.stdin.buffer.read(1024 * 1024))
            result = inspect(request["document"], request["url"], request["config"])
        data = json.dumps(result, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        os.write(reply, data if len(data) <= 8192 else b"null")
    finally:
        os.close(reply)


if __name__ == "__main__":
    main()
