"""Streamlit desktop GUI for the secure vault."""

from __future__ import annotations

import streamlit as st
from .vault import add_entry, get_entry, search_entries


def main() -> None:
    st.set_page_config(page_title="Hide.me-out", page_icon="🔐", layout="centered")
    st.title("Hide.me-out (Streamlit)")

    with st.sidebar:
        st.header("Actions")
        action = st.selectbox("Choose", ["Add", "Get", "Search"])

    master = st.text_input("Master Password", type="password")

    if action == "Add":
        service = st.text_input("Service Name")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        source = st.text_area("Source Info")
        if st.button("Add Entry"):
            ok = add_entry(master, service, username, password, source)
            st.success("Added") if ok else st.error("Failed")

    elif action == "Get":
        service = st.text_input("Service Name")
        if st.button("Get Entry"):
            entry = get_entry(master, service)
            if entry:
                st.json(entry)
            else:
                st.warning("Not found or wrong master password")

    else:
        keyword = st.text_input("Keyword")
        if st.button("Search"):
            results = search_entries(master, keyword)
            st.write(f"Found {len(results)} entries")
            for r in results:
                st.json(r)


if __name__ == "__main__":
    main()