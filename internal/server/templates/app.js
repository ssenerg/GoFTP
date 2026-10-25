"use strict";
// Enhancements for goftp's pages, which work without them. The server's CSP
// admits this script by its hash.
(() => {
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

  const human = n => {
    const units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let i = 0;
    while (n >= 1024 && i < units.length - 1) {
      n /= 1024;
      i++;
    }
    return i ? `${n.toFixed(1)} ${units[i]}` : `${n} B`;
  };

  const icon = id => {
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("class", "i");
    svg.setAttribute("aria-hidden", "true");
    const use = document.createElementNS(ns, "use");
    use.setAttribute("href", "#i-" + id);
    svg.append(use);
    return svg;
  };

  // detailOf reads why the server refused a request: the second line of
  // its plain-text answer, if it has one.
  const detailOf = async resp => {
    if (!resp) return "";
    try {
      return ((await resp.text()).split("\n")[1] || "").trim();
    } catch {
      return "";
    }
  };

  // Confirmations are shown once, not again on reload.
  const params = new URLSearchParams(location.search);
  const shown = ["uploaded", "created", "renamed", "restored", "deleted", "undo", "trashed", "moved", "copied", "to", "done"]
    .filter(p => params.has(p));
  if (shown.length) {
    for (const p of shown) params.delete(p);
    history.replaceState(null, "", location.pathname + (params.size ? "?" + params : ""));
  }

  // Times in the visitor's time zone.
  const when = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
  for (const t of $$("time[datetime]")) {
    const d = new Date(t.dateTime);
    if (!Number.isNaN(d.getTime())) {
      t.title = t.textContent;
      t.textContent = when.format(d);
    }
  }

  // Thumbnails that cannot be made leave the file's icon.
  for (const img of $$("img.thumb")) {
    if (img.complete && !img.naturalWidth) img.remove();
    else img.addEventListener("error", () => img.remove());
  }

  // The viewer: arrows go to the previous and next file, Escape back to the
  // folder.
  const stage = $("#stage");
  if (stage) {
    document.addEventListener("keydown", e => {
      if (e.ctrlKey || e.metaKey || e.altKey || (e.target.closest && e.target.closest("input, textarea, select, video, audio"))) return;
      const to = { ArrowLeft: $("#prev"), ArrowRight: $("#next") }[e.key];
      if (to) location.assign(to.href);
      else if (e.key === "Escape") location.assign(stage.dataset.folder);
    });
  }

  // Filtering the listing; "/" jumps to the filter, Escape clears it.
  // Enter searches the folders in it too, where the filter is a search
  // form.
  const filter = $("#filter");
  if (filter) {
    $("#search").hidden = false;
    const rows = $$("tr[data-name]");
    const none = $("#no-match");
    const apply = () => {
      const q = filter.value.trim().toLowerCase();
      let shown = 0;
      for (const row of rows) {
        row.hidden = q !== "" && !row.dataset.name.includes(q);
        if (!row.hidden) shown++;
      }
      none.hidden = shown > 0;
    };
    filter.addEventListener("input", apply);
    document.addEventListener("keydown", e => {
      const typing = e.target.closest && e.target.closest("input, textarea, select");
      if (e.key === "/" && !typing && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault();
        filter.focus();
      } else if (e.key === "Escape" && e.target === filter) {
        filter.value = "";
        apply();
        filter.blur();
      }
    });
  }

  // The toolbar's popovers open below their button, aligned to its right
  // edge, or to its left edge when they would leave the window that way.
  const place = pop => {
    pop.classList.remove("start");
    if (pop.getBoundingClientRect().left < 0) pop.classList.add("start");
  };

  // New folder: a popover whose errors show in place.
  const box = $(".newfolder");
  if (box) {
    const form = $("form", box);
    const name = $("input[name=folder]", form);
    const error = $(".popover-error", form);
    box.addEventListener("toggle", () => {
      if (!box.open) return;
      place(form);
      name.focus();
    });
    box.addEventListener("keydown", e => {
      if (e.key === "Escape" && box.open) {
        box.open = false;
        $("summary", box).focus();
      }
    });
    document.addEventListener("click", e => {
      if (box.open && !box.contains(e.target)) box.open = false;
    });
    const submit = $("button[type=submit]", form);
    form.addEventListener("submit", async e => {
      e.preventDefault();
      const folder = name.value.trim();
      let status = 400;
      if (folder !== "") {
        submit.disabled = true;
        try {
          status = (await fetch(form.action, { method: "POST", body: new URLSearchParams({ folder }) })).status;
        } catch {
          status = 0;
        }
        submit.disabled = false;
      }
      if (status === 201) {
        location.assign(form.action + "?created=" + encodeURIComponent(folder));
        return;
      }
      error.textContent = {
        0: "The connection was lost. Try again.",
        400: "Folder names cannot be empty or very long, start with a dot, or contain /, \\ or control characters.",
        401: "You were signed out. Sign in and try again.",
        403: "You may not create folders here.",
        409: "Something with this name already exists here.",
      }[status] || `The folder could not be created (error ${status}).`;
      error.hidden = false;
      name.select();
    });
  }

  // Share links: the form asks for a link, which is shown once, with a
  // button to copy it.
  const shareFailed = {
    0: "The connection was lost. Try again.",
    400: "Give the link a password of at least 8 characters, or none.",
    401: "You were signed out. Sign in and try again.",
    403: "You may not share this.",
    404: "It is no longer here. Reload the page.",
    409: "You have too many links. Revoke some under Shared links first.",
    503: "The server is busy. Try again in a moment.",
  };
  const shareForm = (form, name) => {
    const error = $(".popover-error", form);
    const submit = $("button[type=submit]", form);
    // What a use is depends on what the link lets people do.
    const noun = $(".share-noun", form);
    const size = $(".share-size", form);
    const kind = form.elements.kind;
    kind.addEventListener("change", () => {
      noun.textContent = kind.value === "upload" ? "Files" : "Downloads";
      // Only what is sent through a link has a size to limit.
      size.hidden = kind.value !== "upload";
      if (size.hidden) form.elements.max_size.value = "";
    });
    form.addEventListener("submit", async e => {
      e.preventDefault();
      submit.disabled = true;
      let status = 0;
      let link = null;
      try {
        // Not form.action: the form's field named "action" hides it.
        const resp = await fetch(form.getAttribute("action"), {
          method: "POST",
          body: new URLSearchParams(new FormData(form)),
          headers: { Accept: "application/json" },
        });
        status = resp.status;
        if (status === 201) link = await resp.json();
      } catch {
        link = null;
      }
      submit.disabled = false;
      if (!link) {
        error.textContent = shareFailed[status] || `The link could not be created (error ${status}).`;
        error.hidden = false;
        return;
      }
      const password = form.elements.password.value !== "";
      let limit = link.max_uses ? `, for ${link.max_uses} ${link.upload ? "files" : "downloads"} at most` : "";
      if (link.max_size) limit += `, up to ${link.max_size} in all`;
      const title = document.createElement("p");
      title.className = "form-title";
      title.append(icon("check"), "Link created");
      const url = document.createElement("input");
      url.className = "share-url";
      url.readOnly = true;
      url.value = link.url;
      url.setAttribute("aria-label", "The link");
      url.addEventListener("focus", () => url.select());
      const note = document.createElement("p");
      note.className = "share-note";
      note.textContent = `Anyone with it${password ? " and the password" : ""} can ${link.upload ? "upload files to" : "open"} “${name}” ` +
        `until ${when.format(new Date(link.expires_at))}${limit}. Copy it now: it is shown only this once.`;
      const result = document.createElement("div");
      result.className = "share-result";
      result.append(title, url);
      if (navigator.clipboard) {
        const copy = document.createElement("button");
        copy.type = "button";
        copy.className = "btn primary small";
        const label = document.createElement("span");
        label.textContent = "Copy link";
        copy.append(icon("copy"), label);
        copy.addEventListener("click", async () => {
          try {
            await navigator.clipboard.writeText(link.url);
            label.textContent = "Copied";
          } catch {
            url.select();
            label.textContent = "Select and copy";
          }
        });
        const actions = document.createElement("div");
        actions.className = "popover-actions";
        actions.append(copy);
        result.append(actions);
      }
      result.append(note);
      form.replaceChildren(result);
      url.focus();
    });
  };

  // Sharing the folder itself: a popover in the header.
  for (const box of $$(".share-here")) {
    const form = $("form", box);
    shareForm(form, form.dataset.name);
    box.addEventListener("toggle", () => {
      if (!box.open) return;
      place(form);
      if (form.elements.expires) form.elements.expires.focus();
    });
    box.addEventListener("keydown", e => {
      if (e.key === "Escape" && box.open) {
        box.open = false;
        $("summary", box).focus();
      }
    });
    document.addEventListener("click", e => {
      if (box.open && !box.contains(e.target)) box.open = false;
    });
  }

  // Moving and copying entries to another folder: on success, the folder's
  // page says where they went.
  const moveFailed = {
    0: "The connection was lost. Try again.",
    400: "Name the folder as a path, such as /photos/2024.",
    401: "You were signed out. Sign in and try again.",
    403: "You may not do that there.",
    404: "There is no such folder.",
    409: "Something with this name is in that folder already, or is being uploaded.",
  };
  const moveForm = form => {
    const error = $(".popover-error", form);
    form.addEventListener("submit", async e => {
      e.preventDefault();
      const op = e.submitter && e.submitter.value === "move" ? "move" : "copy";
      const body = new URLSearchParams(new FormData(form));
      body.set("op", op);
      const buttons = $$("button", form);
      for (const b of buttons) b.disabled = true;
      let resp = null;
      let status = 0;
      try {
        resp = await fetch(form.getAttribute("action"), { method: "POST", body });
        status = resp.status;
      } catch {
        status = 0;
      }
      for (const b of buttons) b.disabled = false;
      if (status === 201) {
        location.assign(form.getAttribute("action") + `?${op === "move" ? "moved" : "copied"}=${body.getAll("pick").length}` +
          "&to=" + encodeURIComponent(form.elements.into.value.trim()));
        return;
      }
      error.textContent = (await detailOf(resp)) || moveFailed[status] || `It could not be ${op === "move" ? "moved" : "copied"} (error ${status}).`;
      error.hidden = false;
    });
  };

  // Rename, move, share and delete: a popover for each entry, made from a
  // template.
  const itemForms = $("#item-actions");
  if (itemForms) {
    const failed = {
      rename: {
        0: "The connection was lost. Try again.",
        400: "Names cannot be empty or very long, start with a dot, or contain /, \\ or control characters.",
        401: "You were signed out. Sign in and try again.",
        403: "You may not rename this.",
        404: "It is no longer here. Reload the page.",
        409: "Something with this name already exists here, or one of them is being uploaded.",
      },
      delete: {
        0: "The connection was lost. Try again.",
        401: "You were signed out. Sign in and try again.",
        403: "You may not delete this, or something in it.",
        404: "It is no longer here. Reload the page.",
        409: "It, or something in it, is being uploaded right now, or another disk is mounted in it.",
      },
    };
    let open = null;
    const close = focus => {
      if (!open) return;
      open.pop.remove();
      open.link.setAttribute("aria-expanded", "false");
      if (focus) open.link.focus();
      open = null;
    };
    const show = link => {
      const name = link.dataset.item;
      const isDir = link.dataset.dir === "true";
      const pop = document.createElement("div");
      pop.className = "popover item-pop";
      pop.setAttribute("role", "dialog");
      pop.setAttribute("aria-label", link.getAttribute("aria-label"));
      pop.append(itemForms.content.cloneNode(true));
      for (const form of $$("form", pop)) {
        const kind = form.dataset.kind;
        form.hidden = link.dataset[kind] !== "true";
        if (kind === "share") {
          form.elements.path.value = link.dataset.path;
          // Only folders take uploads.
          $(".share-kind", form).hidden = !isDir;
          shareForm(form, name);
          continue;
        }
        if (kind === "move") {
          form.elements.pick.value = name;
          $("button[value=move]", form).hidden = link.dataset.delete !== "true";
          moveForm(form);
          continue;
        }
        const error = $(".popover-error", form);
        const submit = $("button[type=submit]", form);
        form.elements[kind].value = name;
        form.addEventListener("submit", async e => {
          e.preventDefault();
          const to = kind === "rename" ? form.elements.to.value.trim() : "";
          if (kind === "rename" && to === name) {
            close(true);
            return;
          }
          let status = 400;
          let resp = null;
          if (kind === "delete" || to !== "") {
            const body = new URLSearchParams(new FormData(form));
            if (kind === "rename") body.set("to", to);
            submit.disabled = true;
            try {
              resp = await fetch(form.action, { method: "POST", body });
              status = resp.status;
            } catch {
              status = 0;
            }
            submit.disabled = false;
          }
          if (status === 201 || status === 204) {
            // A deletion that went to the trash can be undone.
            const ids = resp.headers.get("Goftp-Trash-Ids");
            location.assign(form.action + (kind === "rename" ? "?renamed=" + encodeURIComponent(to)
              : "?deleted=1" + (ids ? "&undo=" + encodeURIComponent(ids.split(",")[0].trim()) : "")));
            return;
          }
          error.textContent = (await detailOf(resp)) || failed[kind][status] || `It could not be ${kind}d (error ${status}).`;
          error.hidden = false;
          if (kind === "rename") form.elements.to.select();
        });
      }
      const keep = $("form[data-kind=delete]", pop).dataset.trash;
      $(".delete-note", pop).textContent = keep
        ? `Move ${isDir ? "the folder " : ""}“${name}” to the trash? It can be restored from there for ${keep}.`
        : isDir
          ? `Delete the folder “${name}” and everything in it? This cannot be undone.`
          : `Delete “${name}”? This cannot be undone.`;
      link.after(pop);
      // Upwards when it would end below the window and fits above.
      const box = pop.getBoundingClientRect();
      if (box.bottom > innerHeight && box.height < link.getBoundingClientRect().top) pop.classList.add("up");
      link.setAttribute("aria-expanded", "true");
      open = { pop, link };
      const to = $("input[name=to]", pop);
      if (link.dataset.rename === "true") {
        to.value = name;
        to.focus();
        // The name without its extension, ready to be typed over.
        const dot = isDir ? -1 : name.lastIndexOf(".");
        to.setSelectionRange(0, dot > 0 ? dot : name.length);
      } else if (link.dataset.move === "true") {
        $("form[data-kind=move] input[name=into]", pop).focus();
      } else if (link.dataset.share === "true") {
        $("form[data-kind=share] select", pop).focus();
      } else {
        $("form[data-kind=delete] button", pop).focus();
      }
    };
    document.addEventListener("click", e => {
      const link = e.target.closest && e.target.closest("a[data-item]");
      if (link) {
        e.preventDefault();
        const again = open && open.link === link;
        close(false);
        if (!again) show(link);
      } else if (open && !open.pop.contains(e.target)) {
        close(false);
      }
    });
    document.addEventListener("keydown", e => {
      if (e.key === "Escape" && open) close(true);
    });
  }

  // Folder fields suggest the folders in what was typed so far, or those
  // named like its last part.
  let folderList = null;
  let asked = "";
  let suggestTimer;
  const suggest = async field => {
    if (!folderList) {
      folderList = document.createElement("datalist");
      folderList.id = "folders";
      document.body.append(folderList);
    }
    const typed = field.value.trim();
    const cut = typed.lastIndexOf("/") + 1;
    const query = new URLSearchParams({ folders: "1", in: typed.slice(0, cut) || "/", q: typed.slice(cut) });
    if (query.toString() === asked) return;
    asked = query.toString();
    try {
      const resp = await fetch("/.search/?" + query, { headers: { Accept: "application/json" } });
      if (!resp.ok || asked !== query.toString()) return;
      const { results } = await resp.json();
      folderList.replaceChildren(...results.map(r => Object.assign(document.createElement("option"), { value: r.path })));
    } catch {
      // No suggestions, then.
    }
  };
  const folderField = e => e.target.matches && e.target.matches("input[list=folders]");
  document.addEventListener("focusin", e => {
    if (folderField(e)) suggest(e.target);
  });
  document.addEventListener("input", e => {
    if (!folderField(e)) return;
    clearTimeout(suggestTimer);
    suggestTimer = setTimeout(() => suggest(e.target), 150);
  });

  // Picking entries to act on them together: a bar below the list follows
  // the ticks. Its zip downloads as usual; its other forms say in place why
  // they failed, and on success the page says what happened.
  const picked = $("#picked");
  if (picked) {
    const boxes = $$("input[name=pick]");
    const all = $(".pick-all");
    const count = $(".picked-count", picked);
    const clear = $(".picked-clear", picked);
    const shown = b => !b.closest("tr").hidden;
    let last = null;
    const update = () => {
      const n = boxes.filter(b => b.checked).length;
      for (const b of boxes) b.closest("tr").classList.toggle("ticked", b.checked);
      picked.hidden = n === 0;
      count.textContent = `${n} picked`;
      clear.hidden = n === 0;
      const visible = boxes.filter(shown);
      all.checked = visible.length > 0 && visible.every(b => b.checked);
      all.indeterminate = n > 0 && !all.checked;
    };
    picked.classList.add("live");
    all.hidden = false;
    all.addEventListener("change", () => {
      for (const b of boxes.filter(shown)) b.checked = all.checked;
      update();
    });
    for (const [i, b] of boxes.entries()) {
      b.addEventListener("click", e => {
        // Shift-click ticks or unticks the run from the last one clicked.
        if (e.shiftKey && last !== null) {
          for (const other of boxes.slice(Math.min(last, i), Math.max(last, i) + 1).filter(shown)) other.checked = b.checked;
        }
        last = i;
        update();
      });
    }
    clear.addEventListener("click", () => {
      for (const b of boxes) b.checked = false;
      update();
    });
    // Browsers keep ticks across reloads.
    update();

    const pops = $$(".picked-pop", picked);
    for (const box of pops) {
      box.addEventListener("toggle", () => {
        if (!box.open) return;
        for (const other of pops) if (other !== box) other.open = false;
        place($(".popover", box));
        const field = $("input[name=into]", box) || $("button[type=submit]", box);
        field.focus();
      });
      box.addEventListener("keydown", e => {
        if (e.key === "Escape" && box.open) {
          box.open = false;
          $("summary", box).focus();
        }
      });
    }
    document.addEventListener("click", e => {
      for (const box of pops) if (box.open && !box.contains(e.target)) box.open = false;
    });

    const pickFailed = {
      0: "The connection was lost. Try again.",
      400: "Name the folder as a path, such as /photos/2024.",
      401: "You were signed out. Sign in and try again.",
      403: "You may not do that with all of them.",
      404: "One of them, or that folder, is no longer there. Reload the page.",
      409: "One of them is being uploaded right now, or its name is taken there.",
    };
    picked.addEventListener("submit", async e => {
      const op = e.submitter && e.submitter.name === "op" ? e.submitter.value : "";
      if (!op) return;
      e.preventDefault();
      const pop = e.submitter.closest(".popover");
      const error = $(".popover-error", pop);
      const body = new URLSearchParams(new FormData(picked));
      body.set("op", op);
      const action = picked.getAttribute("action");
      const buttons = $$("button", pop);
      for (const b of buttons) b.disabled = true;
      let resp = null;
      let status = 0;
      try {
        resp = await fetch(action, { method: "POST", body });
        status = resp.status;
      } catch {
        status = 0;
      }
      for (const b of buttons) b.disabled = false;
      const n = body.getAll("pick").length;
      if (status === 204 && op === "delete") {
        const ids = (resp.headers.get("Goftp-Trash-Ids") || "").split(",").map(id => id.trim()).filter(Boolean);
        location.assign(action + `?deleted=${n}` + (ids.length === 1 && n === 1 ? "&undo=" + encodeURIComponent(ids[0]) : ids.length ? "&trashed=1" : ""));
        return;
      }
      if (status === 201) {
        location.assign(action + `?${op === "move" ? "moved" : "copied"}=${n}&to=` + encodeURIComponent(body.get("into").trim()));
        return;
      }
      error.textContent = (await detailOf(resp)) || pickFailed[status] || `That failed (error ${status}).`;
      error.hidden = false;
    });
  }

  // Copy buttons, for temporary passwords and links shown once.
  for (const button of $$("button[data-copy]")) {
    const source = document.getElementById(button.dataset.copy);
    if (!source || !navigator.clipboard) continue;
    button.hidden = false;
    button.addEventListener("click", async () => {
      const label = button.lastChild;
      try {
        await navigator.clipboard.writeText(source.textContent.trim());
        label.textContent = "Copied";
      } catch {
        getSelection().selectAllChildren(source);
        label.textContent = "Select and copy";
      }
    });
  }

  // Confirmation popovers close on Escape and on clicks elsewhere.
  for (const box of $$("details.confirm")) {
    box.addEventListener("keydown", e => {
      if (e.key === "Escape" && box.open) {
        box.open = false;
        $("summary", box).focus();
      }
    });
    document.addEventListener("click", e => {
      if (box.open && !box.contains(e.target)) box.open = false;
    });
  }

  // Password fields: show/hide, and a warning while Caps Lock is on.
  for (const input of $$(".pw input")) {
    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "pw-toggle";
    const show = visible => {
      input.type = visible ? "text" : "password";
      toggle.textContent = visible ? "Hide" : "Show";
      toggle.setAttribute("aria-label", visible ? "Hide password" : "Show password");
    };
    show(false);
    toggle.addEventListener("click", () => {
      show(input.type === "password");
      input.focus();
    });
    input.parentElement.append(toggle);

    const caps = input.closest(".field").querySelector(".caps");
    if (caps) {
      const check = e => {
        if (e.getModifierState) caps.hidden = !e.getModifierState("CapsLock");
      };
      input.addEventListener("keydown", check);
      input.addEventListener("keyup", check);
      input.addEventListener("blur", () => { caps.hidden = true; });
    }
  }

  // Choosing a new password: live hints.
  const next = $("input[name=new_password]");
  const confirm = $("input[name=confirm_password]");
  if (next && confirm) {
    const long = $("#hint-length");
    const same = $("#hint-match");
    const update = () => {
      long.classList.toggle("ok", [...next.value].length >= next.minLength);
      const match = confirm.value !== "" && confirm.value === next.value;
      same.classList.toggle("ok", match);
      confirm.setCustomValidity(confirm.value && !match ? "The new passwords do not match." : "");
    };
    next.addEventListener("input", update);
    confirm.addEventListener("input", update);
  }

  // Uploads: files chosen or dropped anywhere on the page are sent one by
  // one, with progress. They resume after a lost connection, and after a
  // reload once the same file is chosen again. Folders are created first,
  // with the files in them going into them.
  const form = $("#upload");
  if (!form) return;
  const picker = $("input[type=file]", form);
  const replace = $("input[name=replace]", form);
  // Upload links take files, but show nothing of the folder.
  const dropbox = form.dataset.dropbox === "true";
  const panel = $("#transfers");
  const overlay = $("#drop");
  let active = 0;
  let failed = 0;
  let done = 0;

  const heading = () => {
    let h = $("h2", panel);
    if (!h) {
      h = document.createElement("h2");
      panel.prepend(h);
    }
    h.replaceChildren();
    const text = document.createElement("span");
    if (active) {
      text.textContent = `Uploading… ${done} of ${done + failed + active} done`;
      h.append(text);
    } else if (done || failed) {
      text.textContent = failed ? `${done} uploaded, ${failed} failed` : `${done} uploaded`;
      const refresh = document.createElement("a");
      refresh.href = form.action;
      refresh.className = "btn small";
      refresh.textContent = dropbox ? "Start over" : "Refresh list";
      h.append(text, refresh);
    } else {
      text.textContent = "Unfinished uploads";
      h.append(text);
    }
    panel.hidden = false;
  };

  const row = (name, meta, id) => {
    const r = document.createElement("div");
    r.className = "transfer";
    const n = document.createElement("span");
    n.className = "transfer-name";
    n.textContent = name;
    const m = document.createElement("span");
    m.className = "transfer-meta";
    m.textContent = meta;
    r.append(icon(id), n, m);
    panel.append(r);
    return { r, m };
  };

  const reason = status => {
    switch (status) {
      case 0: return "The connection was lost.";
      case 400: return "This file name is not allowed.";
      case 401: return "You were signed out. Sign in and try again.";
      case 403:
        if (dropbox) return "This link no longer lets anyone send files.";
        return replace && !replace.checked ? "You may not upload this here." : "You may not upload or replace this here.";
      case 404: return dropbox ? "This link no longer works." : "This folder is no longer here.";
      case 410: return "This link was used as often as it may be.";
      case 409: return replace && !replace.checked
        ? "Already exists: tick “Replace files that already exist”, or rename it."
        : "A file or folder with this name exists or is being uploaded.";
      case 413: return "The file is too large.";
      case 507: return "The server is out of disk space. What arrived is kept: choose the file again later.";
      default: return `Upload failed (error ${status}).`;
    }
  };

  // Uploads speak tus (tus.io): a POST to the folder starts one, PATCH
  // requests send it in parts, and HEAD says how much arrived. Unfinished
  // uploads are remembered per file in this browser.
  const folder = form.getAttribute("action");
  const part = 64 << 20;
  const storePrefix = dir => "goftp-upload\n" + dir + "\n";
  const store = {
    key: (file, replacing, dir) => storePrefix(dir) + [file.name, file.size, file.lastModified, replacing ? 1 : 0].join("\n"),
    get(key) {
      try { return JSON.parse(localStorage.getItem(key)); } catch { return null; }
    },
    set(key, value) {
      try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* storage disabled */ }
    },
    remove(key) {
      try { localStorage.removeItem(key); } catch { /* storage disabled */ }
    },
    keys() {
      try { return Object.keys(localStorage).filter(k => k.startsWith(storePrefix(folder))); } catch { return []; }
    },
  };
  const base64 = s => btoa(Array.from(new TextEncoder().encode(s), b => String.fromCharCode(b)).join(""));

  // request sends one request of the upload t. It resolves with the answer,
  // with status 0 when the connection failed or the request was cancelled.
  const request = (t, method, url, headers, body, onProgress) => new Promise(resolve => {
    const xhr = new XMLHttpRequest();
    xhr.open(method, url);
    xhr.setRequestHeader("Tus-Resumable", "1.0.0");
    for (const [k, v] of Object.entries(headers || {})) xhr.setRequestHeader(k, v);
    if (onProgress) xhr.upload.addEventListener("progress", e => onProgress(e.loaded));
    for (const type of ["load", "error", "abort", "timeout"]) xhr.addEventListener(type, () => resolve(xhr));
    t.xhr = xhr;
    xhr.send(body || null);
  });
  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

  // discard cancels an upload on the server; a request still writing it
  // is cut off soon.
  const discard = async url => {
    for (let i = 0; i < 10; i++) {
      const res = await request({}, "DELETE", url);
      if (res.status !== 423 && res.status !== 0) return;
      await sleep(1000);
    }
  };

  // pause waits before the next try, longer after each failure, and stops
  // waiting when the browser is back online or the upload is cancelled.
  const pause = (t, failures) => new Promise(resolve => {
    let left = Math.min(30, 2 ** (failures - 1));
    let timer;
    const stop = () => {
      clearTimeout(timer);
      removeEventListener("online", stop);
      resolve();
    };
    const tick = () => {
      if (t.cancelled || left <= 0) return stop();
      t.m.textContent = `Connection lost. Trying again in ${left} s…`;
      left--;
      timer = setTimeout(tick, 1000);
    };
    addEventListener("online", stop);
    tick();
  });

  // send uploads file into the folder at the URL dir, showing it as label,
  // and resolves with whether it was stored.
  const send = async (file, dir, label) => {
    const replacing = Boolean(replace && replace.checked);
    const key = store.key(file, replacing, dir);
    for (const r of $$(".transfer.paused", panel)) {
      if (r.dataset.key === key) r.remove();
    }
    const t = row(label, human(file.size), "clock");
    const bar = document.createElement("progress");
    bar.max = 1;
    bar.value = 0;
    const cancel = document.createElement("button");
    cancel.type = "button";
    cancel.className = "icon-btn transfer-btn";
    cancel.setAttribute("aria-label", `Cancel uploading ${file.name}`);
    cancel.title = "Cancel";
    cancel.append(icon("x"));
    cancel.addEventListener("click", () => {
      t.cancelled = true;
      if (t.xhr) t.xhr.abort();
    });
    t.r.append(cancel, bar);
    const show = n => {
      bar.value = file.size ? n / file.size : 1;
      t.m.textContent = `${human(n)} of ${human(file.size)}`;
    };
    const finish = (ok, status) => {
      cancel.remove();
      t.r.classList.add(ok ? "done" : "failed");
      t.r.firstChild.replaceWith(icon(ok ? "check" : "alert"));
      t.m.textContent = ok ? human(file.size) : t.cancelled ? "Cancelled." : reason(status);
      return ok;
    };

    const saved = store.get(key);
    let url = saved && saved.url;
    let offset = null; // what the server has, once known
    let failures = 0;
    let restarted = false;
    for (;;) {
      if (t.cancelled) {
        if (url) discard(url);
        store.remove(key);
        return finish(false);
      }
      let res;
      const patching = url && offset !== null;
      if (!url) {
        let meta = "filename " + base64(file.name) + (replacing ? ",replace " + base64("1") : "");
        // The file keeps when it was last changed.
        if (file.lastModified > 0) meta += ",mtime " + base64(String(Math.floor(file.lastModified / 1000)));
        res = await request(t, "POST", dir, { "Upload-Length": String(file.size), "Upload-Metadata": meta });
        if (res.status === 201) {
          url = new URL(res.getResponseHeader("Location"), location.href).pathname;
          if (file.size === 0) return finish(true);
          store.set(key, { url, name: file.name, size: file.size });
          offset = 0;
          continue;
        }
      } else if (offset === null) {
        res = await request(t, "HEAD", url);
        if (res.status === 200) {
          offset = Number(res.getResponseHeader("Upload-Offset"));
          show(offset);
          continue;
        }
      } else {
        const start = offset;
        res = await request(t, "PATCH", url, { "Upload-Offset": String(start), "Content-Type": "application/offset+octet-stream" },
          file.slice(start, Math.min(file.size, start + part)), n => show(start + n));
        if (res.status === 204) {
          offset = Number(res.getResponseHeader("Upload-Offset"));
          failures = 0;
          show(offset);
          if (offset >= file.size) {
            store.remove(key);
            return finish(true);
          }
          continue;
        }
      }
      if (t.cancelled) continue;
      if (res.status === 404 && url && !restarted) {
        // Expired, or dropped as it could not be stored: start over once,
        // which also says why.
        store.remove(key);
        url = null;
        offset = null;
        restarted = true;
        continue;
      }
      const s = res.status;
      const passing = s === 0 || s === 408 || s === 423 || s === 429 || (s >= 500 && s !== 507) || (s === 409 && patching);
      if (!passing) {
        if (s !== 507) store.remove(key);
        return finish(false, s);
      }
      // Go on from what the server has.
      offset = null;
      if (++failures > 20) return finish(false, 0);
      await pause(t, failures);
    }
  };

  // Uploads into this folder that a reload or a closed tab cut off go on
  // once the same file is chosen again.
  (async () => {
    for (const key of store.keys()) {
      const saved = store.get(key);
      if (!saved || typeof saved.url !== "string") {
        store.remove(key);
        continue;
      }
      const res = await request({}, "HEAD", saved.url);
      if (res.status === 404) store.remove(key);
      if (res.status !== 200) continue;
      const arrived = Number(res.getResponseHeader("Upload-Offset"));
      const t = row(saved.name, `${human(arrived)} of ${human(saved.size)} arrived. Choose the file again to go on.`, "clock");
      t.r.classList.add("paused");
      t.r.dataset.key = key;
      const drop = document.createElement("button");
      drop.type = "button";
      drop.className = "btn small transfer-btn";
      drop.textContent = "Discard";
      drop.addEventListener("click", async () => {
        drop.disabled = true;
        await discard(saved.url);
        store.remove(key);
        t.r.remove();
        if (!$(".transfer", panel)) panel.hidden = true;
      });
      t.r.append(drop);
      heading();
    }
  })();

  // folderAt creates the folders on the way to the path dirs below this
  // one, unless they exist, and resolves with the last one's URL, or with
  // the status that stopped it. made remembers the folders of one upload.
  const folderAt = (dirs, made) => {
    if (!dirs.length) return Promise.resolve({ url: folder });
    const key = dirs.join("/");
    if (!made.has(key)) {
      made.set(key, (async () => {
        const parent = await folderAt(dirs.slice(0, -1), made);
        if (!parent.url) return parent;
        // Named as the server names it.
        const name = dirs[dirs.length - 1].trim();
        let status = 0;
        try {
          status = (await fetch(parent.url, { method: "POST", body: new URLSearchParams({ folder: name }) })).status;
        } catch {
          status = 0;
        }
        // 409: it exists already, and what goes into it is added.
        if (status !== 201 && status !== 409) return { status };
        return { url: parent.url + encodeURIComponent(name) + "/" };
      })());
    }
    return made.get(key);
  };

  // upload sends items, files with the folders they go into ({file, dirs}),
  // after creating the folders in folders, which may be empty.
  const upload = async (items, folders = []) => {
    if (!items.length && !folders.length) return;
    const banner = $("#uploaded");
    if (banner) banner.remove();
    active += items.length;
    heading();
    const made = new Map();
    for (const dirs of folders) {
      const at = await folderAt(dirs, made);
      if (!at.url) {
        row(dirs.join("/") + "/", reason(at.status), "alert").r.classList.add("failed");
        failed++;
        heading();
      }
    }
    for (const { file, dirs } of items) {
      const at = await folderAt(dirs, made);
      const label = [...dirs, file.name].join("/");
      let ok = false;
      if (at.url) {
        ok = await send(file, at.url, label);
      } else {
        row(label, reason(at.status), "alert").r.classList.add("failed");
      }
      active--;
      if (ok) done++;
      else failed++;
      heading();
    }
    if (!active && !failed) location.assign(form.action + "?uploaded=" + done);
  };

  picker.addEventListener("change", () => {
    const files = [...picker.files];
    picker.value = "";
    upload(files.map(file => ({ file, dirs: [] })));
  });

  // Choosing a folder: its files say where in it they are. Dotfiles,
  // which the server refuses, are left out.
  const folders = form.dataset.folders === "true";
  const folderPicker = $(".folder-picker", form);
  const skipped = n => {
    if (!n) return;
    row(`${n} hidden file${n === 1 ? "" : "s"} left out`, "Names starting with a dot are not uploaded.", "alert");
    heading();
  };
  if (folders && folderPicker && "webkitdirectory" in folderPicker) {
    const button = $(".dz-folder", form);
    button.hidden = false;
    button.addEventListener("click", () => folderPicker.click());
    folderPicker.addEventListener("change", () => {
      const items = [];
      let hidden = 0;
      for (const file of folderPicker.files) {
        const parts = (file.webkitRelativePath || file.name).split("/");
        if (parts.some(p => p.startsWith("."))) hidden++;
        else items.push({ file, dirs: parts.slice(0, -1) });
      }
      folderPicker.value = "";
      skipped(hidden);
      upload(items);
    });
  }

  addEventListener("beforeunload", e => {
    if (active) e.preventDefault();
  });

  const carriesFiles = e => e.dataTransfer && [...e.dataTransfer.types].includes("Files");
  let depth = 0;
  document.addEventListener("dragenter", e => {
    if (carriesFiles(e)) {
      depth++;
      overlay.hidden = false;
    }
  });
  document.addEventListener("dragleave", e => {
    if (carriesFiles(e) && --depth <= 0) {
      depth = 0;
      overlay.hidden = true;
    }
  });
  document.addEventListener("dragover", e => {
    if (carriesFiles(e)) e.preventDefault();
  });
  // Dropped folders are read entry by entry; the browser hands them out
  // in batches.
  const entriesOf = dir => new Promise(resolve => {
    const reader = dir.createReader();
    const all = [];
    const next = () => reader.readEntries(batch => {
      if (!batch.length) return resolve(all);
      all.push(...batch);
      next();
    }, () => resolve(all));
    next();
  });
  const fileOf = entry => new Promise(resolve => entry.file(resolve, () => resolve(null)));
  // walk gathers the files and folders of the dropped entry, which is in
  // the folders dirs of what was dropped, and counts the dotfiles left out.
  const walk = async (entry, dirs, found) => {
    if (entry.name.startsWith(".")) {
      found.hidden++;
    } else if (entry.isFile) {
      const file = await fileOf(entry);
      if (file) found.items.push({ file, dirs });
    } else if (entry.isDirectory) {
      const here = [...dirs, entry.name];
      found.folders.push(here);
      for (const e of await entriesOf(entry)) await walk(e, here, found);
    }
  };

  document.addEventListener("drop", async e => {
    if (!carriesFiles(e)) return;
    e.preventDefault();
    depth = 0;
    overlay.hidden = true;
    const found = { items: [], folders: [], hidden: 0 };
    // The entries have to be taken before the event ends.
    const entries = [];
    for (const item of e.dataTransfer.items) {
      const entry = item.webkitGetAsEntry && item.webkitGetAsEntry();
      if (entry && entry.isDirectory && !folders) {
        row(entry.name, "Folders cannot be uploaded here; drop the files inside it.", "alert").r.classList.add("failed");
        failed++;
        heading();
      } else if (entry && entry.isDirectory) {
        entries.push(entry);
      } else if (item.kind === "file") {
        const f = item.getAsFile();
        if (f) found.items.push({ file: f, dirs: [] });
      }
    }
    for (const entry of entries) await walk(entry, [], found);
    skipped(found.hidden);
    upload(found.items, found.folders);
  });
})();
