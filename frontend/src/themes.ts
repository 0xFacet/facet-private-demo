import { useState, useEffect } from 'react'

export interface Theme {
  id: string
  name: string

  // Layout
  page: string
  container: string
  header: string
  logoMark: string
  logoText: string
  headerAddress: string
  main: string
  tagline: string

  // Cards
  card: string
  cardHeader: string
  cardSection: string

  // Balance
  balanceLabel: string
  balanceAmount: string
  balanceUnit: string

  // Form
  input: string
  btnPrimary: string
  btnAccent: string
  btnDanger: string
  btnIcon: string

  // Text
  sectionTitle: string
  helpText: string
  link: string
  infoText: string
  infoStrong: string

  // Notes
  notePill: string

  // Transactions
  txRow: string
  txBadge: { deposit: string; receive: string; self: string; send: string; withdraw: string }
  txAmount: string
  txMeta: string
  txIcon: string

  // Status
  status: { success: string; error: string; pending: string }
  statusText: string

  // Session lost
  sessionBanner: string
  sessionTitle: string
  sessionText: string

  // Footer
  footer: string
  footerLink: string

  // Refresh icon stroke color (for SVG)
  refreshStroke: string
}

// ─── Original Dark Theme ─────────────────────────────────────────────
export const darkTheme: Theme = {
  id: 'dark',
  name: 'Dark',

  page: 'min-h-screen bg-slate-900 text-slate-100 p-4 md:p-6',
  container: 'max-w-md mx-auto',
  header: 'text-center mb-6 py-3',
  logoMark: 'text-4xl font-bold text-cyan-400 inline',
  logoText: 'text-xs font-bold text-cyan-400/70 ml-2 inline-block leading-tight',
  headerAddress: 'text-slate-500 text-xs font-mono mt-2 break-all',
  main: 'space-y-4',
  tagline: 'text-slate-400 text-sm mt-1',

  card: 'bg-slate-800 rounded-xl overflow-hidden',
  cardHeader: 'p-4',
  cardSection: 'p-4',

  balanceLabel: 'font-semibold text-emerald-400',
  balanceAmount: 'text-emerald-400 font-bold text-xl',
  balanceUnit: 'text-sm text-emerald-400/70',

  input: 'bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-slate-100 placeholder-slate-400 focus:outline-none focus:border-cyan-500 disabled:opacity-50 text-sm',
  btnPrimary: 'bg-emerald-500 hover:bg-emerald-400 disabled:bg-slate-600 disabled:cursor-not-allowed text-slate-900 disabled:text-slate-400 font-semibold py-2 px-4 rounded-lg transition whitespace-nowrap text-sm',
  btnAccent: 'bg-cyan-500 hover:bg-cyan-400 disabled:bg-slate-600 disabled:cursor-not-allowed text-slate-900 disabled:text-slate-400 font-semibold py-2 px-4 rounded-lg transition whitespace-nowrap text-sm',
  btnDanger: 'bg-red-500 hover:bg-red-400 text-white font-semibold py-2 px-4 rounded-lg transition',
  btnIcon: 'p-1 text-slate-500 hover:text-cyan-400 disabled:opacity-50 transition',

  sectionTitle: 'text-slate-400 text-sm font-semibold',
  helpText: 'text-slate-500 text-xs',
  link: 'text-cyan-500 hover:text-cyan-400 underline',
  infoText: 'text-sm text-slate-400',
  infoStrong: 'text-slate-300 font-semibold',

  notePill: 'bg-slate-700 rounded px-2 py-1 text-sm text-cyan-400',

  txRow: 'flex items-center justify-between p-2 bg-slate-700 rounded hover:bg-slate-600 transition',
  txBadge: {
    deposit: 'bg-emerald-500/20 text-emerald-400',
    receive: 'bg-purple-500/20 text-purple-400',
    self: 'bg-slate-500/20 text-slate-400',
    send: 'bg-cyan-500/20 text-cyan-400',
    withdraw: 'bg-orange-500/20 text-orange-400',
  },
  txAmount: 'text-slate-300 text-sm',
  txMeta: 'text-slate-500 text-xs',
  txIcon: 'w-4 h-4 text-slate-500',

  status: {
    success: 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30',
    error: 'bg-red-500/20 text-red-400 border border-red-500/30',
    pending: 'bg-orange-500/20 text-orange-400 border border-orange-500/30',
  },
  statusText: 'font-semibold',

  sessionBanner: 'bg-red-500/20 border border-red-500/50 rounded-xl p-4',
  sessionTitle: 'font-semibold mb-1 text-red-400',
  sessionText: 'text-sm mb-3 text-red-400',

  footer: 'mt-8 pt-4 border-t border-slate-700/50 text-center',
  footerLink: 'text-slate-500 hover:text-slate-300 text-sm transition-colors inline-flex items-center gap-1.5',

  refreshStroke: 'currentColor',
}

// ─── Skeuomorphic Theme ──────────────────────────────────────────────
export const skeuomorphicTheme: Theme = {
  id: 'skeuomorphic',
  name: 'Skeuomorphic',

  page: 'min-h-screen bg-black p-4 md:p-6',
  container: 'max-w-md mx-auto',
  header: 'metal-bar rounded-t-xl px-4 py-3',
  logoMark: 'text-4xl font-black text-black skeu-embossed-light inline',
  logoText: 'text-xs font-bold border-l-2 border-[#666] pl-2 leading-tight text-[#333] skeu-embossed-light ml-2 inline-block',
  headerAddress: 'text-[10px] font-mono text-[#666] max-w-[160px] truncate skeu-embossed-light',
  main: 'leather-bg rounded-b-xl p-4 space-y-4',
  tagline: 'text-xs font-bold tracking-widest uppercase text-[#a08060] skeu-embossed-dark text-center py-1',

  card: 'paper-card rounded-lg overflow-hidden',
  cardHeader: 'p-4 border-b border-[#ccc] skeu-gradient-header',
  cardSection: 'p-4 border-b border-[#ccc] skeu-gradient-body',

  balanceLabel: 'font-bold text-lg skeu-embossed text-[#333]',
  balanceAmount: 'text-2xl font-black skeu-embossed text-[#333]',
  balanceUnit: 'text-sm font-bold text-[#666]',

  input: 'inset-field px-3 py-2 text-sm',
  btnPrimary: 'glossy-btn glossy-btn-primary py-2 px-4 text-sm uppercase tracking-wider whitespace-nowrap',
  btnAccent: 'glossy-btn glossy-btn-accent py-2 px-4 text-sm uppercase tracking-wider whitespace-nowrap',
  btnDanger: 'glossy-btn glossy-btn-danger py-2 px-4 text-sm uppercase tracking-wider',
  btnIcon: 'glossy-btn w-6 h-6 flex items-center justify-center !p-0',

  sectionTitle: 'font-bold skeu-embossed text-[#333]',
  helpText: 'text-xs text-[#777] skeu-embossed',
  link: 'text-[#0891b2] hover:text-[#06b6d4] underline font-semibold',
  infoText: 'text-sm text-[#555]',
  infoStrong: 'text-[#333] font-semibold skeu-embossed',

  notePill: 'glossy-btn px-2 py-1 text-sm font-bold',

  txRow: 'glossy-btn flex items-center justify-between p-2 !rounded',
  txBadge: {
    deposit: 'bg-green-200 text-green-800',
    receive: 'bg-purple-200 text-purple-800',
    self: 'bg-gray-200 text-gray-700',
    send: 'bg-cyan-200 text-cyan-800',
    withdraw: 'bg-orange-200 text-orange-800',
  },
  txAmount: 'text-sm font-bold skeu-embossed text-[#333]',
  txMeta: 'text-[#888] text-xs',
  txIcon: 'w-4 h-4 text-[#888] skeu-icon-embossed',

  status: {
    success: 'status-inset border-green-700 bg-green-50 text-green-800',
    error: 'status-inset border-red-700 bg-red-50 text-red-800',
    pending: 'status-inset border-amber-600 bg-amber-50 text-amber-800',
  },
  statusText: 'font-semibold skeu-embossed',

  sessionBanner: 'paper-card rounded-lg p-4 border-2 border-red-400',
  sessionTitle: 'font-bold text-red-800 skeu-embossed mb-1',
  sessionText: 'text-sm text-red-700 mb-3',

  footer: 'mt-4 text-center',
  footerLink: 'text-[#5a4030] hover:text-[#a08060] text-xs font-bold uppercase tracking-wider transition-colors inline-flex items-center gap-1.5 skeu-embossed-dark',

  refreshStroke: '#333',
}

// ─── Brutalist Ticket Theme ─────────────────────────────────────────
export const brutalistTheme: Theme = {
  id: 'brutalist',
  name: 'Brutalist Ticket',

  page: 'min-h-screen bg-[#1a1a1a] text-[#050505] p-4 md:p-6 font-brutalist',
  container: 'max-w-md mx-auto',
  header: 'text-center mb-6 py-3',
  logoMark: 'text-4xl font-bold text-[#0000FF] inline',
  logoText: 'text-xs font-bold text-[#0000FF]/70 ml-2 inline-block leading-tight uppercase tracking-widest',
  headerAddress: 'text-[#999] text-xs font-mono mt-2 break-all',
  main: 'space-y-4',
  tagline: 'text-[#999] text-sm mt-1 uppercase tracking-wider',

  card: 'bg-[#E2E2E2] rounded-2xl overflow-hidden',
  cardHeader: 'p-4 border-b border-dashed border-[#050505]/30',
  cardSection: 'p-4 border-b border-dashed border-[#050505]/30',

  balanceLabel: 'font-bold text-[#050505] uppercase text-xs tracking-wider',
  balanceAmount: 'text-[#050505] font-bold text-xl',
  balanceUnit: 'text-sm text-[#050505]/60',

  input: 'bg-white border border-[#050505] rounded-lg px-3 py-2 text-[#050505] placeholder-[#999] focus:outline-none focus:border-[#0000FF] disabled:opacity-50 text-sm font-brutalist',
  btnPrimary: 'bg-[#0000FF] hover:bg-[#0000CC] disabled:bg-[#999] disabled:cursor-not-allowed text-white font-bold py-2 px-4 rounded-lg transition whitespace-nowrap text-sm uppercase tracking-wider',
  btnAccent: 'bg-white hover:bg-[#0000FF] hover:text-white disabled:bg-[#999] disabled:cursor-not-allowed text-[#050505] border border-[#050505] font-bold py-2 px-4 rounded-lg transition whitespace-nowrap text-sm uppercase tracking-wider',
  btnDanger: 'bg-red-600 hover:bg-red-500 text-white font-bold py-2 px-4 rounded-lg transition uppercase tracking-wider',
  btnIcon: 'p-1 text-[#050505]/50 hover:text-[#0000FF] disabled:opacity-50 transition',

  sectionTitle: 'text-[#050505] text-sm font-bold uppercase tracking-wider',
  helpText: 'text-[#050505]/50 text-xs',
  link: 'text-[#0000FF] hover:text-[#0000CC] underline',
  infoText: 'text-sm text-[#050505]/70',
  infoStrong: 'text-[#050505] font-bold',

  notePill: 'bg-[#0000FF]/10 rounded px-2 py-1 text-sm text-[#0000FF] font-bold',

  txRow: 'flex items-center justify-between p-2 bg-white rounded-lg hover:bg-[#0000FF]/5 transition border border-dashed border-[#050505]/20',
  txBadge: {
    deposit: 'bg-emerald-200 text-emerald-800',
    receive: 'bg-purple-200 text-purple-800',
    self: 'bg-gray-200 text-gray-700',
    send: 'bg-[#0000FF]/10 text-[#0000FF]',
    withdraw: 'bg-orange-200 text-orange-800',
  },
  txAmount: 'text-[#050505] text-sm font-bold',
  txMeta: 'text-[#050505]/50 text-xs',
  txIcon: 'w-4 h-4 text-[#050505]/40',

  status: {
    success: 'bg-emerald-100 text-emerald-800 border border-emerald-300',
    error: 'bg-red-100 text-red-800 border border-red-300',
    pending: 'bg-orange-100 text-orange-800 border border-orange-300',
  },
  statusText: 'font-bold uppercase text-xs tracking-wider',

  sessionBanner: 'bg-red-100 border-2 border-dashed border-red-500 rounded-2xl p-4',
  sessionTitle: 'font-bold mb-1 text-red-700 uppercase',
  sessionText: 'text-sm mb-3 text-red-600',

  footer: 'mt-8 pt-4 border-t border-dashed border-[#999]/30 text-center',
  footerLink: 'text-[#999] hover:text-[#0000FF] text-sm transition-colors inline-flex items-center gap-1.5 uppercase tracking-wider',

  refreshStroke: '#050505',
}

// ─── Japanese Receipt Theme ─────────────────────────────────────────
export const receiptTheme: Theme = {
  id: 'receipt',
  name: 'Japanese Receipt',

  page: 'min-h-screen bg-[#e8eadd] text-black p-4 md:p-6 font-receipt',
  container: 'max-w-md mx-auto',
  header: 'text-center mb-6 py-3 border-b-2 border-black',
  logoMark: 'text-4xl font-bold text-black inline',
  logoText: 'text-xs font-bold text-black ml-2 inline-block leading-tight',
  headerAddress: 'text-black/60 text-xs font-mono mt-2 break-all',
  main: 'space-y-4',
  tagline: 'text-black/60 text-sm mt-1',

  card: 'bg-[#e8eadd] border-2 border-black overflow-hidden',
  cardHeader: 'p-4 border-b-2 border-black',
  cardSection: 'p-4 border-b-2 border-black',

  balanceLabel: 'font-bold text-black text-xs',
  balanceAmount: 'text-black font-bold text-xl',
  balanceUnit: 'text-sm text-black/60',

  input: 'bg-transparent border-2 border-black px-3 py-2 text-black placeholder-black/40 focus:outline-none focus:border-black disabled:opacity-50 text-sm font-receipt',
  btnPrimary: 'bg-transparent hover:bg-gray-200 disabled:bg-transparent disabled:cursor-not-allowed text-black border-2 border-black font-bold py-2 px-4 transition whitespace-nowrap text-sm font-receipt',
  btnAccent: 'bg-transparent hover:bg-gray-200 disabled:bg-transparent disabled:cursor-not-allowed text-black border-2 border-black font-bold py-2 px-4 transition whitespace-nowrap text-sm font-receipt',
  btnDanger: 'bg-transparent hover:bg-red-100 text-red-700 border-2 border-red-700 font-bold py-2 px-4 transition font-receipt',
  btnIcon: 'p-1 text-black/50 hover:text-black disabled:opacity-50 transition',

  sectionTitle: 'text-black text-sm font-bold',
  helpText: 'text-black/50 text-xs',
  link: 'text-black underline hover:text-black/70',
  infoText: 'text-sm text-black/70',
  infoStrong: 'text-black font-bold',

  notePill: 'border-2 border-black px-2 py-1 text-sm text-black font-bold',

  txRow: 'flex items-center justify-between p-2 border-2 border-black hover:bg-black/5 transition',
  txBadge: {
    deposit: 'border border-black bg-transparent text-black',
    receive: 'border border-black bg-transparent text-black',
    self: 'border border-black bg-transparent text-black',
    send: 'border border-black bg-transparent text-black',
    withdraw: 'border border-black bg-transparent text-black',
  },
  txAmount: 'text-black text-sm font-bold',
  txMeta: 'text-black/50 text-xs',
  txIcon: 'w-4 h-4 text-black/50',

  status: {
    success: 'border-2 border-black bg-transparent text-black',
    error: 'border-2 border-red-700 bg-transparent text-red-700',
    pending: 'border-2 border-black bg-transparent text-black',
  },
  statusText: 'font-bold',

  sessionBanner: 'border-2 border-red-700 p-4',
  sessionTitle: 'font-bold mb-1 text-red-700',
  sessionText: 'text-sm mb-3 text-red-600',

  footer: 'mt-8 pt-4 border-t-2 border-black text-center',
  footerLink: 'text-black/50 hover:text-black text-sm transition-colors inline-flex items-center gap-1.5',

  refreshStroke: '#000000',
}

// ─── Acid Brutalist Theme ───────────────────────────────────────────
export const acidTheme: Theme = {
  id: 'acid',
  name: 'Acid Brutalist',

  page: 'min-h-screen bg-white text-black p-4 md:p-6',
  container: 'max-w-md mx-auto',
  header: 'text-center mb-6 py-3 border-b border-black',
  logoMark: 'text-4xl font-bold text-black inline font-acid-display uppercase',
  logoText: 'text-xs font-bold text-black ml-2 inline-block leading-tight uppercase tracking-widest',
  headerAddress: 'text-black/50 text-xs font-mono mt-2 break-all',
  main: 'space-y-4',
  tagline: 'text-black/60 text-sm mt-1 uppercase tracking-wider',

  card: 'bg-white border border-black overflow-hidden',
  cardHeader: 'p-4 border-b border-black',
  cardSection: 'p-4 border-b border-black',

  balanceLabel: 'font-bold text-black uppercase text-xs tracking-wider',
  balanceAmount: 'text-black font-bold text-xl font-acid-display',
  balanceUnit: 'text-sm text-black/60 uppercase',

  input: 'bg-white border border-black px-3 py-2 text-black placeholder-black/30 focus:outline-none focus:border-[#00FF00] disabled:opacity-50 text-sm',
  btnPrimary: 'bg-black hover:bg-[#00FF00] hover:text-black disabled:bg-gray-300 disabled:cursor-not-allowed text-white font-bold py-2 px-4 transition whitespace-nowrap text-sm uppercase tracking-wider',
  btnAccent: 'bg-white hover:bg-[#00FF00] disabled:bg-gray-300 disabled:cursor-not-allowed text-black border border-black font-bold py-2 px-4 transition whitespace-nowrap text-sm uppercase tracking-wider',
  btnDanger: 'bg-white hover:bg-red-500 hover:text-white text-red-600 border border-red-600 font-bold py-2 px-4 transition uppercase tracking-wider',
  btnIcon: 'p-1 text-black/50 hover:text-[#00FF00] disabled:opacity-50 transition',

  sectionTitle: 'text-black text-sm font-bold uppercase tracking-wider',
  helpText: 'text-black/40 text-xs uppercase',
  link: 'text-[#00FF00] hover:text-black underline',
  infoText: 'text-sm text-black/60',
  infoStrong: 'text-black font-bold',

  notePill: 'bg-[#00FF00]/20 border border-black px-2 py-1 text-sm text-black font-bold',

  txRow: 'flex items-center justify-between p-2 border border-black hover:bg-[#00FF00]/10 transition',
  txBadge: {
    deposit: 'bg-[#00FF00]/20 text-black border border-black',
    receive: 'bg-purple-100 text-black border border-black',
    self: 'bg-gray-100 text-black border border-black',
    send: 'bg-cyan-100 text-black border border-black',
    withdraw: 'bg-orange-100 text-black border border-black',
  },
  txAmount: 'text-black text-sm font-bold',
  txMeta: 'text-black/40 text-xs',
  txIcon: 'w-4 h-4 text-black/40',

  status: {
    success: 'bg-[#00FF00]/20 text-black border border-black',
    error: 'bg-red-100 text-red-800 border border-black',
    pending: 'bg-orange-100 text-orange-800 border border-black',
  },
  statusText: 'font-bold uppercase text-xs tracking-wider',

  sessionBanner: 'border border-red-600 p-4',
  sessionTitle: 'font-bold mb-1 text-red-600 uppercase',
  sessionText: 'text-sm mb-3 text-red-500',

  footer: 'mt-8 pt-4 border-t border-black text-center',
  footerLink: 'text-black/40 hover:text-[#00FF00] text-sm transition-colors inline-flex items-center gap-1.5 uppercase tracking-wider',

  refreshStroke: '#000000',
}

// ─── Blue Dashboard Theme ───────────────────────────────────────────
export const blueprintTheme: Theme = {
  id: 'blueprint',
  name: 'Blue Dashboard',

  page: 'min-h-screen bg-[#0039d6] text-white p-4 md:p-6',
  container: 'max-w-md mx-auto',
  header: 'text-center mb-6 py-3',
  logoMark: 'text-4xl font-bold text-white inline',
  logoText: 'text-xs font-bold text-white/70 ml-2 inline-block leading-tight',
  headerAddress: 'text-white/50 text-xs font-mono mt-2 break-all',
  main: 'space-y-4',
  tagline: 'text-white/70 text-sm mt-1',

  card: 'bg-[#f0f1f3] border border-[#0039d6]/30 overflow-hidden text-[#0039d6]',
  cardHeader: 'p-4 border-b border-[#0039d6]/20',
  cardSection: 'p-4 border-b border-[#0039d6]/20',

  balanceLabel: 'font-semibold text-[#0039d6]',
  balanceAmount: 'text-[#0039d6] font-bold text-xl',
  balanceUnit: 'text-sm text-[#0039d6]/60',

  input: 'bg-white border border-[#0039d6]/30 px-3 py-2 text-[#0039d6] placeholder-[#0039d6]/30 focus:outline-none focus:border-[#0039d6] disabled:opacity-50 text-sm',
  btnPrimary: 'bg-[#0039d6] hover:bg-[#002db0] disabled:bg-gray-400 disabled:cursor-not-allowed text-white font-semibold py-2 px-4 transition whitespace-nowrap text-sm',
  btnAccent: 'bg-white hover:bg-[#0039d6] hover:text-white disabled:bg-gray-400 disabled:cursor-not-allowed text-[#0039d6] border border-[#0039d6] font-semibold py-2 px-4 transition whitespace-nowrap text-sm',
  btnDanger: 'bg-red-600 hover:bg-red-500 text-white font-semibold py-2 px-4 transition',
  btnIcon: 'p-1 text-[#0039d6]/50 hover:text-[#0039d6] disabled:opacity-50 transition',

  sectionTitle: 'text-[#0039d6] text-sm font-semibold',
  helpText: 'text-[#0039d6]/40 text-xs',
  link: 'text-[#0039d6] hover:text-[#002db0] underline font-semibold',
  infoText: 'text-sm text-[#0039d6]/60',
  infoStrong: 'text-[#0039d6] font-semibold',

  notePill: 'bg-[#0039d6]/10 px-2 py-1 text-sm text-[#0039d6] font-semibold',

  txRow: 'flex items-center justify-between p-2 bg-white hover:bg-[#0039d6]/5 transition border border-[#0039d6]/10',
  txBadge: {
    deposit: 'bg-emerald-100 text-emerald-700',
    receive: 'bg-purple-100 text-purple-700',
    self: 'bg-gray-100 text-gray-600',
    send: 'bg-[#0039d6]/10 text-[#0039d6]',
    withdraw: 'bg-orange-100 text-orange-700',
  },
  txAmount: 'text-[#0039d6] text-sm font-semibold',
  txMeta: 'text-[#0039d6]/40 text-xs',
  txIcon: 'w-4 h-4 text-[#0039d6]/40',

  status: {
    success: 'bg-emerald-100 text-emerald-700 border border-emerald-300',
    error: 'bg-red-100 text-red-700 border border-red-300',
    pending: 'bg-orange-100 text-orange-700 border border-orange-300',
  },
  statusText: 'font-semibold',

  sessionBanner: 'bg-red-100 border border-red-400 p-4',
  sessionTitle: 'font-semibold mb-1 text-red-700',
  sessionText: 'text-sm mb-3 text-red-600',

  footer: 'mt-8 pt-4 border-t border-white/20 text-center',
  footerLink: 'text-white/50 hover:text-white text-sm transition-colors inline-flex items-center gap-1.5',

  refreshStroke: '#0039d6',
}

// ─── Braun Hardware Theme ───────────────────────────────────────────
// Three semantic colors: red-orange (action), muted green (value/money),
// warm grey (structure). Least effective difference within each role.
export const braunTheme: Theme = {
  id: 'braun',
  name: 'Braun Hardware',

  page: 'min-h-screen bg-[#22252a] text-[#9a938b] p-4 md:p-6 font-braun',
  container: 'max-w-md mx-auto',
  header: 'text-center mb-6 py-3 border-b border-[#3e424a]',
  logoMark: 'text-4xl font-bold text-[#ddd7cf] inline',
  logoText: 'text-xs font-bold text-[#706b64] ml-2 inline-block leading-tight uppercase tracking-widest',
  headerAddress: 'text-[#706b64] text-xs font-mono mt-2 break-all',
  main: 'space-y-4',
  tagline: 'text-[#706b64] text-sm mt-1 uppercase tracking-wider',

  card: 'braun-card rounded-lg overflow-hidden',
  cardHeader: 'p-4 border-b border-[#3e424a]',
  cardSection: 'p-4 border-b border-[#3e424a]',

  balanceLabel: 'font-bold text-[#6b9e6b] uppercase text-xs tracking-wider',
  balanceAmount: 'text-[#7ab87a] font-bold text-xl',
  balanceUnit: 'text-sm text-[#6b9e6b]',

  input: 'braun-input px-3 py-2 text-sm rounded',
  btnPrimary: 'bg-[#e8503a] hover:bg-[#d4472f] disabled:bg-[#353940] disabled:cursor-not-allowed text-white disabled:text-[#706b64] font-bold py-2 px-4 rounded transition whitespace-nowrap text-sm uppercase tracking-wider font-braun',
  btnAccent: 'bg-transparent hover:bg-[#e8503a] hover:text-white disabled:bg-[#353940] disabled:cursor-not-allowed text-[#e8503a] border border-[#e8503a]/50 font-bold py-2 px-4 rounded transition whitespace-nowrap text-sm uppercase tracking-wider font-braun',
  btnDanger: 'bg-transparent hover:bg-red-900/30 text-red-400 border border-red-400/40 font-bold py-2 px-4 rounded transition uppercase tracking-wider font-braun',
  btnIcon: 'p-1 text-[#706b64] hover:text-[#c4bdb5] disabled:opacity-50 transition',

  sectionTitle: 'text-[#c4bdb5] text-sm font-bold uppercase tracking-wider',
  helpText: 'text-[#706b64] text-xs',
  link: 'text-[#e8503a]/80 hover:text-[#e8503a] underline',
  infoText: 'text-sm text-[#9a938b]',
  infoStrong: 'text-[#c4bdb5] font-bold',

  notePill: 'bg-[#6b9e6b]/10 border border-[#6b9e6b]/25 rounded px-2 py-1 text-sm text-[#7ab87a] font-bold',

  txRow: 'flex items-center justify-between p-2 bg-[#272a30] rounded hover:bg-[#2e3138] transition',
  txBadge: {
    deposit: 'bg-[#6b9e6b]/15 text-[#7ab87a]',
    receive: 'bg-purple-900/20 text-purple-400/80',
    self: 'bg-[#353940] text-[#706b64]',
    send: 'bg-[#e8503a]/10 text-[#e8503a]',
    withdraw: 'bg-amber-900/20 text-amber-400/80',
  },
  txAmount: 'text-[#c4bdb5] text-sm',
  txMeta: 'text-[#706b64] text-xs',
  txIcon: 'w-4 h-4 text-[#56524c]',

  status: {
    success: 'bg-[#6b9e6b]/10 text-[#7ab87a] border border-[#6b9e6b]/20',
    error: 'bg-red-900/15 text-red-400/80 border border-red-500/20',
    pending: 'bg-amber-900/15 text-amber-400/80 border border-amber-500/20',
  },
  statusText: 'font-bold uppercase text-xs tracking-wider',

  sessionBanner: 'bg-red-900/15 border border-red-500/30 rounded-lg p-4',
  sessionTitle: 'font-bold mb-1 text-red-400 uppercase',
  sessionText: 'text-sm mb-3 text-red-400/70',

  footer: 'mt-8 pt-4 border-t border-[#3e424a] text-center',
  footerLink: 'text-[#56524c] hover:text-[#9a938b] text-sm transition-colors inline-flex items-center gap-1.5 uppercase tracking-wider',

  refreshStroke: '#6b9e6b',
}

// ─── LEGO Instructions Theme ────────────────────────────────────────
export const legoTheme: Theme = {
  id: 'lego',
  name: 'LEGO Instructions',

  page: 'min-h-screen bg-black text-black p-4 md:p-6 font-lego',
  container: 'max-w-md mx-auto',
  header: 'text-center mb-6 py-3 bg-[#FFDCB4] border border-black',
  logoMark: 'text-4xl font-bold text-black inline',
  logoText: 'text-xs font-bold text-black ml-2 inline-block leading-tight',
  headerAddress: 'text-black/60 text-xs font-mono mt-2 break-all',
  main: 'space-y-4',
  tagline: 'text-black/60 text-sm mt-1',

  card: 'bg-[#FFDCB4] border border-black overflow-hidden',
  cardHeader: 'p-4 border-b border-black bg-[#D8F2D8]',
  cardSection: 'p-4 border-b border-black',

  balanceLabel: 'font-bold text-black text-xs',
  balanceAmount: 'text-black font-bold text-xl',
  balanceUnit: 'text-sm text-black/60',

  input: 'bg-white border border-black px-3 py-2 text-black placeholder-black/30 focus:outline-none focus:border-black disabled:opacity-50 text-sm font-lego',
  btnPrimary: 'bg-[#D8F2D8] hover:bg-[#c0e8c0] disabled:bg-gray-300 disabled:cursor-not-allowed text-black border border-black font-bold py-2 px-4 transition whitespace-nowrap text-sm font-lego',
  btnAccent: 'bg-[#FFDCB4] hover:bg-[#ffd0a0] disabled:bg-gray-300 disabled:cursor-not-allowed text-black border border-black font-bold py-2 px-4 transition whitespace-nowrap text-sm font-lego',
  btnDanger: 'bg-red-200 hover:bg-red-300 text-red-900 border border-black font-bold py-2 px-4 transition font-lego',
  btnIcon: 'p-1 text-black/50 hover:text-black disabled:opacity-50 transition',

  sectionTitle: 'text-black text-sm font-bold',
  helpText: 'text-black/50 text-xs',
  link: 'text-black underline hover:text-black/70',
  infoText: 'text-sm text-black/70',
  infoStrong: 'text-black font-bold',

  notePill: 'bg-[#D8F2D8] border border-black px-2 py-1 text-sm text-black font-bold',

  txRow: 'flex items-center justify-between p-2 bg-[#D8F2D8] border border-black hover:bg-[#c0e8c0] transition',
  txBadge: {
    deposit: 'bg-[#D8F2D8] text-black border border-black',
    receive: 'bg-[#FFDCB4] text-black border border-black',
    self: 'bg-white text-black border border-black',
    send: 'bg-[#D8F2D8] text-black border border-black',
    withdraw: 'bg-[#FFDCB4] text-black border border-black',
  },
  txAmount: 'text-black text-sm font-bold',
  txMeta: 'text-black/50 text-xs',
  txIcon: 'w-4 h-4 text-black/50',

  status: {
    success: 'bg-[#D8F2D8] text-black border border-black',
    error: 'bg-red-200 text-red-900 border border-black',
    pending: 'bg-[#FFDCB4] text-black border border-black',
  },
  statusText: 'font-bold',

  sessionBanner: 'bg-red-200 border border-black p-4',
  sessionTitle: 'font-bold mb-1 text-red-900',
  sessionText: 'text-sm mb-3 text-red-800',

  footer: 'mt-8 pt-4 border-t border-[#FFDCB4]/50 text-center',
  footerLink: 'text-[#FFDCB4]/70 hover:text-[#FFDCB4] text-sm transition-colors inline-flex items-center gap-1.5',

  refreshStroke: '#000000',
}

// ─── Retro Terminal Theme ───────────────────────────────────────────
export const terminalTheme: Theme = {
  id: 'terminal',
  name: 'Retro Terminal',

  page: 'min-h-screen bg-[#404040] text-[#FF4B2B] p-4 md:p-6 font-terminal',
  container: 'max-w-md mx-auto',
  header: 'text-center mb-6 py-3 border-b border-[#FF4B2B]',
  logoMark: 'text-4xl font-bold text-[#FF4B2B] inline uppercase',
  logoText: 'text-xs font-bold text-[#FF4B2B]/70 ml-2 inline-block leading-tight uppercase tracking-widest',
  headerAddress: 'text-[#FF4B2B]/50 text-xs font-mono mt-2 break-all uppercase',
  main: 'space-y-4',
  tagline: 'text-[#FF4B2B]/60 text-sm mt-1 uppercase tracking-wider',

  card: 'border border-[#FF4B2B] overflow-hidden',
  cardHeader: 'p-4 border-b border-[#FF4B2B]',
  cardSection: 'p-4 border-b border-[#FF4B2B]',

  balanceLabel: 'font-bold text-[#FF4B2B]/70 uppercase text-xs tracking-wider',
  balanceAmount: 'text-[#FF4B2B] font-bold text-xl',
  balanceUnit: 'text-sm text-[#FF4B2B]/60 uppercase',

  input: 'bg-transparent border border-[#FF4B2B] px-3 py-2 text-[#FF4B2B] placeholder-[#FF4B2B]/30 focus:outline-none focus:border-[#FF4B2B] focus:shadow-[0_0_5px_rgba(255,75,43,0.3)] disabled:opacity-50 text-sm font-terminal uppercase',
  btnPrimary: 'bg-[#FF4B2B] hover:bg-[#ff6b4a] disabled:bg-[#404040] disabled:border-[#FF4B2B]/30 disabled:text-[#FF4B2B]/30 disabled:cursor-not-allowed text-[#404040] font-bold py-2 px-4 transition whitespace-nowrap text-sm uppercase tracking-wider font-terminal',
  btnAccent: 'bg-transparent hover:bg-[#FF4B2B] hover:text-[#404040] disabled:opacity-30 disabled:cursor-not-allowed text-[#FF4B2B] border border-[#FF4B2B] font-bold py-2 px-4 transition whitespace-nowrap text-sm uppercase tracking-wider font-terminal',
  btnDanger: 'bg-transparent hover:bg-red-600 hover:text-white text-red-500 border border-red-500 font-bold py-2 px-4 transition uppercase tracking-wider font-terminal',
  btnIcon: 'p-1 text-[#FF4B2B]/50 hover:text-[#FF4B2B] disabled:opacity-50 transition',

  sectionTitle: 'text-[#FF4B2B] text-sm font-bold uppercase tracking-wider',
  helpText: 'text-[#FF4B2B]/40 text-xs uppercase',
  link: 'text-[#FF4B2B] hover:text-[#ff6b4a] underline',
  infoText: 'text-sm text-[#FF4B2B]/60',
  infoStrong: 'text-[#FF4B2B] font-bold',

  notePill: 'border border-[#FF4B2B] px-2 py-1 text-sm text-[#FF4B2B] font-bold uppercase',

  txRow: 'flex items-center justify-between p-2 border border-[#FF4B2B]/50 hover:border-[#FF4B2B] transition',
  txBadge: {
    deposit: 'border border-[#FF4B2B] text-[#FF4B2B]',
    receive: 'border border-[#FF4B2B] text-[#FF4B2B]',
    self: 'border border-[#FF4B2B]/50 text-[#FF4B2B]/50',
    send: 'border border-[#FF4B2B] text-[#FF4B2B]',
    withdraw: 'border border-[#FF4B2B] text-[#FF4B2B]',
  },
  txAmount: 'text-[#FF4B2B] text-sm font-bold',
  txMeta: 'text-[#FF4B2B]/40 text-xs uppercase',
  txIcon: 'w-4 h-4 text-[#FF4B2B]/40',

  status: {
    success: 'border border-[#FF4B2B] text-[#FF4B2B]',
    error: 'border border-red-500 text-red-500',
    pending: 'border border-[#FF4B2B]/50 text-[#FF4B2B]/50',
  },
  statusText: 'font-bold uppercase text-xs tracking-wider',

  sessionBanner: 'border border-red-500 p-4',
  sessionTitle: 'font-bold mb-1 text-red-500 uppercase',
  sessionText: 'text-sm mb-3 text-red-500/80',

  footer: 'mt-8 pt-4 border-t border-[#FF4B2B]/30 text-center',
  footerLink: 'text-[#FF4B2B]/40 hover:text-[#FF4B2B] text-sm transition-colors inline-flex items-center gap-1.5 uppercase tracking-wider',

  refreshStroke: '#FF4B2B',
}

// ─── Editorial Navy Theme ───────────────────────────────────────────
export const editorialTheme: Theme = {
  id: 'editorial',
  name: 'Editorial Navy',

  page: 'min-h-screen bg-[#e0e0e0] text-[#180085] p-4 md:p-6 font-editorial',
  container: 'max-w-md mx-auto',
  header: 'text-center mb-6 py-3 border-b border-[#180085]/20',
  logoMark: 'text-4xl font-bold text-[#180085] inline italic',
  logoText: 'text-xs font-bold text-[#180085]/70 ml-2 inline-block leading-tight italic',
  headerAddress: 'text-[#180085]/40 text-xs font-mono mt-2 break-all',
  main: 'space-y-4',
  tagline: 'text-[#180085]/50 text-sm mt-1 italic',

  card: 'bg-[#F7F7F2] shadow-md overflow-hidden rounded-sm',
  cardHeader: 'p-4 border-b border-[#180085]/10',
  cardSection: 'p-4 border-b border-[#180085]/10',

  balanceLabel: 'font-semibold text-[#180085]/70 italic text-sm',
  balanceAmount: 'text-[#180085] font-bold text-xl',
  balanceUnit: 'text-sm text-[#180085]/50 italic',

  input: 'bg-white border border-[#180085]/20 rounded-sm px-3 py-2 text-[#180085] placeholder-[#180085]/30 focus:outline-none focus:border-[#180085] disabled:opacity-50 text-sm font-editorial',
  btnPrimary: 'bg-[#180085] hover:bg-[#120066] disabled:bg-gray-400 disabled:cursor-not-allowed text-[#F7F7F2] font-semibold py-2 px-4 rounded-sm transition whitespace-nowrap text-sm font-editorial',
  btnAccent: 'bg-[#F7F7F2] hover:bg-[#180085] hover:text-[#F7F7F2] disabled:bg-gray-400 disabled:cursor-not-allowed text-[#180085] border border-[#180085]/30 font-semibold py-2 px-4 rounded-sm transition whitespace-nowrap text-sm font-editorial',
  btnDanger: 'bg-red-700 hover:bg-red-600 text-white font-semibold py-2 px-4 rounded-sm transition font-editorial',
  btnIcon: 'p-1 text-[#180085]/40 hover:text-[#180085] disabled:opacity-50 transition',

  sectionTitle: 'text-[#180085] text-sm font-semibold italic',
  helpText: 'text-[#180085]/40 text-xs italic',
  link: 'text-[#180085] hover:text-[#120066] underline italic',
  infoText: 'text-sm text-[#180085]/60',
  infoStrong: 'text-[#180085] font-semibold',

  notePill: 'bg-[#180085]/10 rounded-sm px-2 py-1 text-sm text-[#180085] font-semibold italic',

  txRow: 'flex items-center justify-between p-2 bg-white rounded-sm shadow-sm hover:shadow-md transition border border-[#180085]/5',
  txBadge: {
    deposit: 'bg-emerald-50 text-emerald-800',
    receive: 'bg-purple-50 text-purple-800',
    self: 'bg-gray-50 text-gray-600',
    send: 'bg-[#180085]/5 text-[#180085]',
    withdraw: 'bg-orange-50 text-orange-800',
  },
  txAmount: 'text-[#180085] text-sm font-semibold',
  txMeta: 'text-[#180085]/40 text-xs italic',
  txIcon: 'w-4 h-4 text-[#180085]/30',

  status: {
    success: 'bg-emerald-50 text-emerald-800 border border-emerald-200',
    error: 'bg-red-50 text-red-800 border border-red-200',
    pending: 'bg-amber-50 text-amber-800 border border-amber-200',
  },
  statusText: 'font-semibold italic',

  sessionBanner: 'bg-red-50 border border-red-300 rounded-sm shadow-md p-4',
  sessionTitle: 'font-bold mb-1 text-red-800 italic',
  sessionText: 'text-sm mb-3 text-red-700',

  footer: 'mt-8 pt-4 border-t border-[#180085]/10 text-center',
  footerLink: 'text-[#180085]/40 hover:text-[#180085] text-sm transition-colors inline-flex items-center gap-1.5 italic',

  refreshStroke: '#180085',
}

// ─── Streetwear Theme ───────────────────────────────────────────────
export const streetwearTheme: Theme = {
  id: 'streetwear',
  name: 'Streetwear',

  page: 'min-h-screen bg-[#080808] text-[#F2E8DC] p-4 md:p-6 font-streetwear-body',
  container: 'max-w-md mx-auto',
  header: 'text-center mb-6 py-3 border-b-[3px] border-[#F2E8DC]',
  logoMark: 'text-4xl text-[#FFC0CB] inline font-streetwear-display uppercase',
  logoText: 'text-xs font-bold text-[#FF8C55] ml-2 inline-block leading-tight uppercase tracking-widest',
  headerAddress: 'text-[#F2E8DC]/50 text-xs font-mono mt-2 break-all uppercase',
  main: 'space-y-4',
  tagline: 'text-[#FF8C55] text-sm mt-1 uppercase tracking-wider font-bold',

  card: 'bg-[#F2E8DC] text-black border-[3px] border-black overflow-hidden',
  cardHeader: 'p-4 border-b-[3px] border-black bg-[#FFC0CB]',
  cardSection: 'p-4 border-b-[3px] border-black',

  balanceLabel: 'font-bold text-black uppercase text-xs tracking-wider font-streetwear-display',
  balanceAmount: 'text-black font-bold text-xl font-streetwear-display',
  balanceUnit: 'text-sm text-black/60 uppercase',

  input: 'bg-[#F2E8DC] border-2 border-black px-3 py-2 text-black placeholder-black/30 focus:outline-none focus:border-[#FF8C55] disabled:opacity-50 text-sm font-streetwear-body',
  btnPrimary: 'bg-[#FF8C55] hover:bg-[#ff7a3a] disabled:bg-gray-500 disabled:cursor-not-allowed text-black font-bold py-2 px-4 transition whitespace-nowrap text-sm uppercase tracking-wider font-streetwear-display',
  btnAccent: 'bg-[#FFC0CB] hover:bg-[#ffb0be] disabled:bg-gray-500 disabled:cursor-not-allowed text-black font-bold py-2 px-4 transition whitespace-nowrap text-sm uppercase tracking-wider font-streetwear-display',
  btnDanger: 'bg-red-600 hover:bg-red-500 text-white font-bold py-2 px-4 transition uppercase tracking-wider font-streetwear-display',
  btnIcon: 'p-1 text-black/50 hover:text-[#FF8C55] disabled:opacity-50 transition',

  sectionTitle: 'text-black text-sm font-bold uppercase tracking-wider font-streetwear-display',
  helpText: 'text-black/50 text-xs uppercase',
  link: 'text-[#FF8C55] hover:text-[#FFC0CB] underline font-bold',
  infoText: 'text-sm text-black/70',
  infoStrong: 'text-black font-bold',

  notePill: 'bg-[#FFC0CB] border-2 border-black px-2 py-1 text-sm text-black font-bold uppercase',

  txRow: 'flex items-center justify-between p-2 bg-[#FFC0CB] border-2 border-black hover:bg-[#ffb0be] transition',
  txBadge: {
    deposit: 'bg-[#2F5233] text-white',
    receive: 'bg-[#FFC0CB] text-black border border-black',
    self: 'bg-[#F2E8DC] text-black border border-black',
    send: 'bg-[#FF8C55] text-black',
    withdraw: 'bg-[#080808] text-[#F2E8DC]',
  },
  txAmount: 'text-black text-sm font-bold',
  txMeta: 'text-black/50 text-xs uppercase',
  txIcon: 'w-4 h-4 text-black/50',

  status: {
    success: 'bg-[#2F5233] text-white border-2 border-black',
    error: 'bg-red-500 text-white border-2 border-black',
    pending: 'bg-[#FF8C55] text-black border-2 border-black',
  },
  statusText: 'font-bold uppercase text-xs tracking-wider',

  sessionBanner: 'bg-red-500 border-[3px] border-black p-4 text-white',
  sessionTitle: 'font-bold mb-1 text-white uppercase font-streetwear-display',
  sessionText: 'text-sm mb-3 text-white/90',

  footer: 'mt-8 pt-4 border-t-[3px] border-[#F2E8DC]/20 text-center',
  footerLink: 'text-[#F2E8DC]/40 hover:text-[#FF8C55] text-sm transition-colors inline-flex items-center gap-1.5 uppercase tracking-wider',

  refreshStroke: '#FF8C55',
}

// ─── Theme Registry ──────────────────────────────────────────────────
export const themes: Theme[] = [darkTheme, skeuomorphicTheme, brutalistTheme, receiptTheme, acidTheme, blueprintTheme, braunTheme, legoTheme, terminalTheme, editorialTheme, streetwearTheme]

const STORAGE_KEY = 'facet-private-theme'

export function useTheme() {
  const [themeId, setThemeId] = useState(() => {
    try {
      return localStorage.getItem(STORAGE_KEY) || 'dark'
    } catch {
      return 'dark'
    }
  })

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, themeId)
    } catch { /* ignore */ }
  }, [themeId])

  const theme = themes.find(t => t.id === themeId) || darkTheme

  return { theme, themeId, setThemeId, themes }
}
