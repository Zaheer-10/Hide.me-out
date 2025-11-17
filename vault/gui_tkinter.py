"""Tkinter desktop GUI for the secure vault."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox

from .vault import add_entry, get_entry, search_entries


class VaultApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Hide.me-out (Tkinter)")
        self.geometry("600x500")

        self.master_var = tk.StringVar()
        ttk.Label(self, text="Master Password").pack(anchor="w")
        ttk.Entry(self, textvariable=self.master_var, show="*").pack(fill="x")

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True)

        self._build_add_tab()
        self._build_get_tab()
        self._build_search_tab()

    def _build_add_tab(self) -> None:
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Add")
        self.service_var = tk.StringVar()
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.source_var = tk.StringVar()
        ttk.Label(frame, text="Service Name").pack(anchor="w")
        ttk.Entry(frame, textvariable=self.service_var).pack(fill="x")
        ttk.Label(frame, text="Username").pack(anchor="w")
        ttk.Entry(frame, textvariable=self.username_var).pack(fill="x")
        ttk.Label(frame, text="Password").pack(anchor="w")
        ttk.Entry(frame, textvariable=self.password_var, show="*").pack(fill="x")
        ttk.Label(frame, text="Source Info").pack(anchor="w")
        ttk.Entry(frame, textvariable=self.source_var).pack(fill="x")
        ttk.Button(frame, text="Add", command=self._do_add).pack(pady=8)

    def _build_get_tab(self) -> None:
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Get")
        self.get_service_var = tk.StringVar()
        ttk.Label(frame, text="Service Name").pack(anchor="w")
        ttk.Entry(frame, textvariable=self.get_service_var).pack(fill="x")
        ttk.Button(frame, text="Get", command=self._do_get).pack(pady=8)
        self.get_result = tk.Text(frame, height=10)
        self.get_result.pack(fill="both", expand=True)

    def _build_search_tab(self) -> None:
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Search")
        self.search_keyword_var = tk.StringVar()
        ttk.Label(frame, text="Keyword").pack(anchor="w")
        ttk.Entry(frame, textvariable=self.search_keyword_var).pack(fill="x")
        ttk.Button(frame, text="Search", command=self._do_search).pack(pady=8)
        self.search_result = tk.Text(frame, height=10)
        self.search_result.pack(fill="both", expand=True)

    def _do_add(self) -> None:
        ok = add_entry(
            self.master_var.get(),
            self.service_var.get(),
            self.username_var.get(),
            self.password_var.get(),
            self.source_var.get(),
        )
        messagebox.showinfo("Result", "Added" if ok else "Failed")

    def _do_get(self) -> None:
        entry = get_entry(self.master_var.get(), self.get_service_var.get())
        self.get_result.delete("1.0", tk.END)
        self.get_result.insert(tk.END, str(entry) if entry else "Not found or wrong master password")

    def _do_search(self) -> None:
        results = search_entries(self.master_var.get(), self.search_keyword_var.get())
        self.search_result.delete("1.0", tk.END)
        for r in results:
            self.search_result.insert(tk.END, str(r) + "\n")


def main() -> None:
    app = VaultApp()
    app.mainloop()


if __name__ == "__main__":
    main()