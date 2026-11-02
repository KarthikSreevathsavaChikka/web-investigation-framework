import { EntityDemoPage } from "./pages/EntityDemoPage";
import { Activity, BriefcaseBusiness, LayoutDashboard, Menu, PlusCircle, Search, ShieldCheck, X } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { DashboardPage } from "./pages/DashboardPage";
import { InvestigationPage } from "./pages/InvestigationPage";
import { InvestigationsPage } from "./pages/InvestigationsPage";
import { JobsPage } from "./pages/JobsPage";
import { NewInvestigationPage } from "./pages/NewInvestigationPage";
import { api } from "./api";
import { DarkwebPage } from "./pages/DarkwebPage";

const navigation = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/new", label: "New scrape", icon: PlusCircle },
  { to: "/entity-demo", label: "Entity discovery", icon: Search },
  { to: "/investigations", label: "Scraping results", icon: Search },
  { to: "/external-jobs", label: "External jobs", icon: BriefcaseBusiness },
  { to: "/darkweb", label: "Dark-web references", icon: ShieldCheck },
];

export function App() {
  const [open, setOpen] = useState(false);
  return <div className="app-shell">
    <aside className={open ? "sidebar sidebar-open" : "sidebar"}>
      <div className="brand"><span className="brand-mark"><ShieldCheck size={22}/></span><span>Web Scraping Console</span></div>
      <button className="icon-button close-menu" aria-label="Close navigation" onClick={() => setOpen(false)}><X/></button>
      <nav>{navigation.map(({ to, label, icon: Icon, end }) =>
        <NavLink key={to} to={to} end={end} onClick={() => setOpen(false)} className={({ isActive }) => isActive ? "nav-link active" : "nav-link"}>
          <Icon size={19}/><span>{label}</span>
        </NavLink>)}</nav>
      <div className="sidebar-note"><Activity size={16}/><span>Live data from FastAPI</span></div>
    </aside>
    {open && <button className="scrim" aria-label="Close navigation" onClick={() => setOpen(false)}/>}
    <main>
      <header className="topbar"><button className="icon-button menu-button" onClick={() => setOpen(true)} aria-label="Open navigation"><Menu/></button><span>Web scraping operations</span><ApiStatus/></header>
      <div className="page"><Routes>
        <Route path="/entity-demo" element={<EntityDemoPage/>}/>
        <Route path="/" element={<DashboardPage/>}/>
        <Route path="/investigations" element={<InvestigationsPage/>}/>
        <Route path="/new" element={<NewInvestigationPage/>}/>
        <Route path="/darkweb" element={<DarkwebPage/>}/>
        <Route path="/investigations/:id" element={<InvestigationPage/>}/>
        <Route path="/external-jobs" element={<JobsPage/>}/>
        <Route path="*" element={<Navigate to="/" replace/>}/>
      </Routes></div>
    </main>
  </div>;
}

function ApiStatus() {
  const query = useQuery({ queryKey: ["health"], queryFn: api.health, refetchInterval: 15000, retry: 1 });
  const connected = query.data?.status === "ready";
  return <span className={connected ? "api-status" : "api-status api-offline"}><span className="status-dot"/>{query.isLoading ? "Checking API" : connected ? "API connected" : "API unavailable"}</span>;
}
