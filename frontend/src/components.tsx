import type { ReactNode } from "react";
import type { Status } from "./types";

export function PageHeader({ eyebrow, title, description, actions }: { eyebrow?: string; title: string; description: string; actions?: ReactNode }) {
  return <div className="page-header"><div>{eyebrow && <div className="eyebrow">{eyebrow}</div>}<h1>{title}</h1><p>{description}</p></div>{actions && <div className="header-actions">{actions}</div>}</div>;
}

export function StatCard({ label, value, hint }: { label: string; value: string | number; hint: string }) {
  return <article className="stat-card"><span>{label}</span><strong>{value}</strong><small>{hint}</small></article>;
}

export function StatusBadge({ status }: { status: Status | string }) {
  return <span className={`badge badge-${status.toLowerCase()}`}>{status.replaceAll("_", " ")}</span>;
}

export function EmptyState({ title, body }: { title: string; body: string }) {
  return <div className="empty-state"><strong>{title}</strong><p>{body}</p></div>;
}

export function ErrorState({ error }: { error: Error }) {
  return <div className="error-state"><strong>Could not load this view</strong><span>{error.message}</span></div>;
}

export function Loading() { return <div className="loading"><span/><span/><span/></div>; }

export function formatDate(value: string | null | undefined) {
  if (!value) return "Not available";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : new Intl.DateTimeFormat("en-IN", { dateStyle: "medium", timeStyle: "short", timeZone: "Asia/Kolkata" }).format(date);
}

export function shortId(value: string) { return value.length > 20 ? `${value.slice(0, 17)}…` : value; }
