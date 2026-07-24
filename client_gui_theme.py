#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Design tokens for Asteria Client v4.4 UI."""

# Modern dark theme — slate + emerald accent
COLORS = {
    "bg":           "#0b1120",
    "sidebar":      "#0f172a",
    "card":         "#1e293b",
    "card_hover":   "#243044",
    "card_active":  "#1d3a2f",
    "accent":       "#134e4a",
    "accent_soft":  "#115e59",
    "green":        "#10b981",
    "green_hover":  "#34d399",
    "red":          "#f43f5e",
    "red_hover":    "#fb7185",
    "orange":       "#f59e0b",
    "orange_hover": "#fbbf24",
    "blue":         "#3b82f6",
    "blue_hover":   "#60a5fa",
    "text":         "#cbd5e1",
    "text_dim":     "#64748b",
    "text_bright":  "#f8fafc",
    "border":       "#334155",
    "entry_bg":     "#0f172a",
    "status_dot_on":  "#34d399",
    "status_dot_off": "#f43f5e",
    "nav_active":   "#1e3a5f",
    "nav_hover":    "#1e293b",
}

SERVICE_ICONS = {
    "RDP":   "🖥",
    "MSSQL": "🗃",
    "MYSQL": "🐬",
    "FTP":   "📁",
    "SSH":   "🔐",
    "HTTP":  "🌐",
    "SMB":   "📂",
}

SIDEBAR_WIDTH = 220

# Sidebar navigation layout (fixed icon gutter — emoji widths vary)
NAV_ITEM_HEIGHT = 40
NAV_ICON_WIDTH = 32
NAV_PAD_X = 10
NAV_ICON_TEXT_GAP = 10
NAV_FONT_ICON = 16
NAV_FONT_LABEL = 13

