from __future__ import annotations

import os
from pathlib import Path

import pandas as pd
import streamlit as st

from core.time_utils import format_ist

from ui.api_client import APIClientError
from ui.job_status import get_api_client
from virustotal.client import expand_stored_report
from virustotal.report import build_batch_docx
from virustotal.storage import VirusTotalRepository


_ECHARTS_SOURCE = (Path(__file__).parent / "assets" / "echarts.min.js").read_text(encoding="utf-8")
_RELATIONSHIP_GRAPH = st.components.v2.component(
    "virustotal_relationship_graph",
    html="""
<div class="graph-shell">
  <div class="graph-loading">Loading interactive relationship graph…</div>
  <div class="graph-canvas" role="img" aria-label="Interactive domain relationship graph"></div>
</div>
""",
    css="""
.graph-shell {
  width: 100%; height: 590px; position: relative; overflow: hidden;
  border: 1px solid var(--st-border-color); border-radius: var(--st-border-radius);
  background: #0e1117;
}
.graph-canvas { width: 100%; height: 100%; }
.graph-loading {
  position: absolute; inset: 0; display: grid; place-items: center;
  color: #cbd5e1; font: 500 14px var(--st-font);
}
""",
    js=_ECHARTS_SOURCE + r"""

export default function(component) {
  const { data, parentElement, setStateValue } = component;
  const canvas = parentElement.querySelector(".graph-canvas");
  const loading = parentElement.querySelector(".graph-loading");
  if (!canvas) return;
  loading.style.display = "none";

  const existing = echarts.getInstanceByDom(canvas);
  if (existing) existing.dispose();
  const chart = echarts.init(canvas, null, { renderer: "canvas" });
  chart.setOption({
    backgroundColor: "#0e1117",
    animationDurationUpdate: 600,
    animationEasingUpdate: "quinticInOut",
    tooltip: {
      trigger: "item", renderMode: "richText",
      backgroundColor: "#171b26", borderColor: "#475569",
      textStyle: { color: "#f8fafc", fontSize: 13 },
      formatter: (params) => {
        if (params.dataType === "edge") {
          return `${params.data.source} → ${params.data.target}\n${params.data.relationship || "Related"}`;
        }
        const item = params.data;
        const lines = [item.name, `Type: ${item.kind || "Relationship"}`];
        if (item.summary) lines.push(item.summary);
        if (item.date) lines.push(`Observed: ${item.date}`);
        return lines.join("\n");
      }
    },
    legend: {
      top: 12, left: 14, textStyle: { color: "#cbd5e1" },
      data: data.categories.map((category) => category.name)
    },
    toolbox: {
      right: 16, top: 8,
      iconStyle: { borderColor: "#cbd5e1" },
      emphasis: { iconStyle: { borderColor: "#ff0054" } },
      feature: {
        restore: {},
        saveAsImage: { name: `${data.target}-relationships`, backgroundColor: "#0e1117" }
      }
    },
    series: [{
      type: "graph", layout: "force", roam: true, draggable: true,
      data: data.nodes, links: data.links, categories: data.categories,
      edgeSymbol: ["none", "arrow"], edgeSymbolSize: [0, 9],
      label: { show: true, position: "right", color: "#f8fafc", fontSize: 13, formatter: "{b}" },
      labelLayout: { hideOverlap: true, moveOverlap: "shiftY" },
      lineStyle: { color: "source", opacity: 0.72, width: 2, curveness: 0.08 },
      emphasis: {
        focus: "adjacency", lineStyle: { width: 4, opacity: 1 },
        label: { show: true, fontWeight: "bold" }
      },
      force: { repulsion: 430, edgeLength: [110, 210], gravity: 0.08, friction: 0.62 }
    }]
  }, true);

  chart.on("click", (params) => {
    if (params.dataType === "node") {
      setStateValue("selected", {
        id: params.data.id, name: params.data.name, kind: params.data.kind,
        summary: params.data.summary || ""
      });
    }
  });
  const observer = new ResizeObserver(() => chart.resize());
  observer.observe(canvas);
  return () => { observer.disconnect(); chart.dispose(); };
}
""",
)


def _display_value(value) -> str:
    if value is None or value == "":
        return "Unavailable"
    return str(value)


def _analysis_rows(report: dict) -> list[dict]:
    payload = report.get("raw_response") or {}
    attributes = (payload.get("data") or {}).get("attributes") or {}
    rows = []
    for key, result in (attributes.get("last_analysis_results") or {}).items():
        rows.append({
            "Engine": result.get("engine_name") or key,
            "Category": result.get("category") or "unknown",
            "Result": result.get("result") or "",
            "Method": result.get("method") or "",
        })
    order = {"malicious": 0, "suspicious": 1, "undetected": 2, "harmless": 3, "timeout": 4}
    return sorted(rows, key=lambda row: (order.get(str(row["Category"]), 9), str(row["Engine"]).casefold()))


def _relationship_graph_data(report: dict) -> tuple[list[dict], list[dict]]:
    """Build a stable summary graph from relationship data already stored locally."""
    relationships = report.get("relationships") or {}
    target = report.get("target") or report.get("object_id") or "Target"

    def relationship_count(name: str) -> int:
        relation = relationships.get(name) or {}
        count = relation.get("count")
        if isinstance(count, (int, float)):
            return int(count)
        return len(relation.get("items") or [])

    nodes = [
        {"id": "target", "label": target, "kind": "Target", "count": 1, "x": 1.0, "y": 1.0},
        {
            "id": "subdomains",
            "label": f"{relationship_count('subdomains')} subdomain(s)",
            "kind": "Subdomains",
            "count": relationship_count("subdomains"),
            "x": 0.3,
            "y": 1.55,
        },
        {
            "id": "resolutions",
            "label": f"{relationship_count('resolutions')} resolution(s)",
            "kind": "Resolutions",
            "count": relationship_count("resolutions"),
            "x": 1.7,
            "y": 0.45,
        },
    ]
    edges = [
        {"x": 0.3, "y": 1.55, "x2": 1.0, "y2": 1.0, "relationship": "subdomain of"},
        {"x": 1.0, "y": 1.0, "x2": 1.7, "y2": 0.45, "relationship": "resolves to"},
    ]
    return nodes, edges


def _echarts_relationship_data(report: dict) -> dict:
    relationships = report.get("relationships") or {}
    target = report.get("target") or report.get("object_id") or "Target"
    categories = [
        {"name": "Target"}, {"name": "Relationship"}, {"name": "Subdomain"},
        {"name": "Resolution"}, {"name": "Certificate"}, {"name": "Registration"},
    ]
    nodes = [{
        "id": "target", "name": target, "kind": "Target", "category": 0,
        "symbol": "circle", "symbolSize": 78, "summary": "Selected domain",
        "itemStyle": {"color": "#ff0054", "borderColor": "#f8fafc", "borderWidth": 3},
    }]
    links = []

    for relation_name, group_label, item_kind, category, color in (
        ("subdomains", "Subdomains", "Subdomain", 2, "#a855f7"),
        ("resolutions", "Resolutions", "Resolution", 3, "#22b8cf"),
    ):
        relation = relationships.get(relation_name) or {}
        items = relation.get("items") or []
        count = relation.get("count") if isinstance(relation.get("count"), (int, float)) else len(items)
        group_id = f"group:{relation_name}"
        nodes.append({
            "id": group_id, "name": f"{group_label} ({int(count)})", "kind": "Relationship",
            "category": 1, "symbol": "roundRect", "symbolSize": [126, 48],
            "summary": f"{int(count)} relationship(s) reported by VirusTotal",
            "itemStyle": {"color": "#1e293b", "borderColor": color, "borderWidth": 3},
        })
        links.append({"source": "target", "target": group_id, "relationship": relation_name})
        for index, item in enumerate(items[:30]):
            attributes = item.get("attributes") or {}
            value = attributes.get("ip_address") or item.get("id") or f"{item_kind} {index + 1}"
            item_id = f"{relation_name}:{index}:{value}"
            nodes.append({
                "id": item_id, "name": str(value), "kind": item_kind, "category": category,
                "symbolSize": 42, "summary": f"VirusTotal {item_kind.lower()} relationship",
                "date": attributes.get("date") or attributes.get("last_modification_date") or "",
                "itemStyle": {"color": color, "borderColor": "#f8fafc", "borderWidth": 2},
            })
            links.append({"source": group_id, "target": item_id, "relationship": item_kind.lower()})

    certificate = report.get("https_certificate") or {}
    if certificate:
        issuer = certificate.get("issuer") or {}
        validity = certificate.get("validity") or {}
        nodes.append({
            "id": "certificate", "name": "HTTPS certificate", "kind": "Certificate", "category": 4,
            "symbol": "diamond", "symbolSize": 58,
            "summary": f"Issuer: {_display_value(issuer.get('CN') or issuer.get('common_name'))}",
            "date": validity.get("not_before") or report.get("last_https_certificate_date") or "",
            "itemStyle": {"color": "#f59e0b", "borderColor": "#f8fafc", "borderWidth": 2},
        })
        links.append({"source": "target", "target": "certificate", "relationship": "secured by"})

    if report.get("whois") or report.get("registrar"):
        nodes.append({
            "id": "registration", "name": "WHOIS / registration", "kind": "Registration", "category": 5,
            "symbol": "roundRect", "symbolSize": [142, 48],
            "summary": f"Registrar: {_display_value(report.get('registrar'))}",
            "date": report.get("creation_date") or report.get("whois_date") or "",
            "itemStyle": {"color": "#64748b", "borderColor": "#f8fafc", "borderWidth": 2},
        })
        links.append({"source": "target", "target": "registration", "relationship": "registered as"})

    return {"target": target, "nodes": nodes, "links": links, "categories": categories}


def _render_relationship_graph(report: dict) -> None:
    result = _RELATIONSHIP_GRAPH(
        data=_echarts_relationship_data(report),
        key=f"vt_echarts_{report.get('object_id') or report.get('target')}",
        height=590,
        width="stretch",
        on_selected_change=lambda: None,
    )
    st.caption(
        "Drag nodes to rearrange the graph. Scroll to zoom, drag the background to pan, hover for details, "
        "and use the toolbar to restore or export it. No additional VirusTotal API request is made."
    )
    selected = getattr(result, "selected", None)
    if selected:
        with st.container(border=True):
            st.markdown(f"**{selected.get('name', 'Selected node')}**")
            st.caption(f"{selected.get('kind', 'Relationship')} · {selected.get('summary') or 'No additional details'}")


def _render_detection(report: dict) -> None:
    stats = report.get("analysis_stats") or {}
    with st.container(horizontal=True):
        for name in ("malicious", "suspicious", "harmless", "undetected", "timeout"):
            st.metric(name.capitalize(), stats.get(name, 0), border=True)

    chart_rows = [
        {"Verdict": name.replace("_", " ").title(), "Engines": value}
        for name, value in stats.items()
        if isinstance(value, (int, float))
    ]
    if chart_rows:
        st.bar_chart(pd.DataFrame(chart_rows), x="Verdict", y="Engines", horizontal=True)

    rows = _analysis_rows(report)
    st.subheader("Security vendor analysis")
    if rows:
        categories = sorted({str(row["Category"]) for row in rows})
        selected = st.pills(
            "Filter verdicts",
            categories,
            selection_mode="multi",
            key=f"vt_verdict_filter_{report.get('object_id')}",
        )
        visible = [row for row in rows if not selected or row["Category"] in selected]
        st.dataframe(
            pd.DataFrame(visible),
            hide_index=True,
            column_config={
                "Engine": st.column_config.TextColumn(width="medium"),
                "Category": st.column_config.TextColumn(width="small"),
                "Result": st.column_config.TextColumn(width="medium"),
            },
        )
    else:
        st.info("No per-engine analysis results were returned for this target.")


def _render_details(report: dict) -> None:
    metadata = [
        ("Target type", report.get("target_type")),
        ("Reputation", report.get("reputation")),
        ("Registrar", report.get("registrar")),
        ("Country", report.get("country")),
        ("Network", report.get("network")),
        ("AS owner", report.get("as_owner")),
        ("Creation date", format_ist(report.get("creation_date"))),
        ("Registry update", format_ist(report.get("last_update_date"))),
        ("Last analysis", format_ist(report.get("last_analysis_date"))),
        ("Last submission", format_ist(report.get("last_submission_date"))),
        ("WHOIS observed", format_ist(report.get("whois_date"))),
        ("JARM fingerprint", report.get("jarm")),
    ]
    st.subheader("Domain and registration details")
    st.dataframe(
        pd.DataFrame(
            [{"Property": label, "Value": _display_value(value)} for label, value in metadata]
        ),
        hide_index=True,
        column_config={"Property": st.column_config.TextColumn(width="medium")},
    )

    categories = report.get("categories") or {}
    tags = report.get("tags") or []
    with st.container(border=True):
        st.markdown("**Classification**")
        st.write("Tags: " + (", ".join(tags) if tags else "Unavailable"))
        if categories:
            st.dataframe(
                pd.DataFrame(
                    [{"Provider": provider, "Category": category} for provider, category in categories.items()]
                ),
                hide_index=True,
            )
        else:
            st.caption("No categories were returned.")

    dns_records = report.get("dns_records") or []
    st.subheader("Last observed DNS records")
    st.caption(f"Observed: {report.get('last_dns_records_date') or 'Unavailable'}")
    if dns_records:
        st.dataframe(
            pd.DataFrame([
                {"Type": row.get("type"), "Value": _display_value(row.get("value")), "TTL": row.get("ttl")}
                for row in dns_records
            ]),
            hide_index=True,
        )
    else:
        st.caption("No DNS records were returned.")

    certificate = report.get("https_certificate") or {}
    st.subheader("Last HTTPS certificate")
    st.caption(f"Observed: {report.get('last_https_certificate_date') or 'Unavailable'}")
    if certificate:
        subject = certificate.get("subject") or {}
        issuer = certificate.get("issuer") or {}
        validity = certificate.get("validity") or {}
        certificate_rows = [
            ("Subject", subject.get("CN") or subject.get("common_name")),
            ("Issuer", issuer.get("CN") or issuer.get("common_name")),
            ("Serial number", certificate.get("serial_number")),
            ("Thumbprint", certificate.get("thumbprint") or certificate.get("thumbprint_sha256")),
            ("Valid from", validity.get("not_before")),
            ("Valid until", validity.get("not_after")),
        ]
        st.dataframe(
            pd.DataFrame([{"Property": label, "Value": _display_value(value)} for label, value in certificate_rows]),
            hide_index=True,
        )
    else:
        st.caption("No certificate details were returned.")

    whois = (report.get("whois") or "").strip()
    st.subheader("WHOIS record")
    if whois:
        with st.expander("View complete WHOIS record"):
            st.code(whois, language=None, wrap_lines=True)
    else:
        st.caption("No WHOIS record was returned.")


def _render_relations(report: dict) -> None:
    relationships = report.get("relationships") or {}
    st.subheader("Graph summary")
    _render_relationship_graph(report)

    for name, heading in (("resolutions", "Passive DNS resolutions"), ("subdomains", "Subdomains")):
        relation = relationships.get(name) or {}
        items = relation.get("items") or []
        count = relation.get("count")
        st.subheader(f"{heading} ({count if count is not None else len(items)})")
        if items:
            rows = []
            for related in items:
                attributes = related.get("attributes") or {}
                rows.append({
                    "Value": attributes.get("ip_address") or related.get("id"),
                    "Type": related.get("type"),
                    "Date": attributes.get("date") or attributes.get("last_modification_date") or "",
                })
            st.dataframe(pd.DataFrame(rows), hide_index=True)
        else:
            st.caption("No relationship items were included under the current API access.")

    ranks = report.get("popularity_ranks") or {}
    st.subheader("Popularity rankings")
    if ranks:
        st.dataframe(
            pd.DataFrame([
                {"Source": source, "Rank": details.get("rank"), "Timestamp": details.get("timestamp")}
                for source, details in ranks.items()
            ]),
            hide_index=True,
        )
    else:
        st.caption("No popularity rankings were returned.")


def _render_community(report: dict) -> None:
    votes = report.get("total_votes") or {}
    with st.container(horizontal=True):
        st.metric("Harmless votes", votes.get("harmless", 0), border=True)
        st.metric("Malicious votes", votes.get("malicious", 0), border=True)
        st.metric("Reputation", report.get("reputation", 0), border=True)
    st.info(
        "Community comments are not included in this stored API response. Open the VirusTotal record "
        "to review comments when your account and API access permit them.",
        icon=":material/forum:",
    )


@st.fragment(run_every=2)
def _render_pending_batch() -> None:
    job_id = st.session_state.get("virustotal_job_id")
    if not job_id:
        return
    try:
        job = get_api_client().get_job(job_id)
    except APIClientError as exc:
        st.error(f"Could not refresh VirusTotal batch: {exc}")
        return
    st.info(f"VirusTotal batch {job_id}: {job['status']}", icon=":material/pending:")
    if job["status"] == "COMPLETED":
        st.session_state.virustotal_batch_id = job.get("result", {}).get("batch_id")
        st.session_state.pop("virustotal_job_id", None)
        st.rerun()
    elif job["status"] in {"FAILED", "CANCELLED"}:
        st.session_state.pop("virustotal_job_id", None)
        st.error(job.get("error") or "VirusTotal batch did not complete.")


def render_virustotal_workspace() -> None:
    repository = VirusTotalRepository()
    configured = bool(os.getenv("VIRUSTOTAL_API_KEY", "").strip())

    st.title(":material/security: VirusTotal intelligence")
    st.caption(
        "View combined VirusTotal reports generated automatically from the domains selected "
        "in Web Scraping."
    )
    if not configured:
        st.warning(
            "VirusTotal is not configured. Add VIRUSTOTAL_API_KEY to .env and recreate the app and workers.",
            icon=":material/key:",
        )
    _render_pending_batch()

    batches = repository.list_batches()
    if not batches:
        st.info(
            "No combined VirusTotal report is available. Select domains in Web Scraping, "
            "then start evidence discovery."
        )
        return

    options = {
        f"{item.get('brand') or 'Selected domains'} · {item['domain_count']} domains · {format_ist(item['retrieved_at'])}": item["id"]
        for item in batches
    }
    current = st.session_state.get("virustotal_batch_id")
    labels = list(options)
    selected = st.selectbox(
        "Combined VirusTotal reports", labels,
        index=next((i for i, label in enumerate(labels) if options[label] == current), 0),
    )
    batch = repository.get_batch(options[selected])
    if not batch:
        return
    st.session_state.virustotal_batch_id = batch["id"]

    results = batch.get("results") or []
    completed = [item for item in results if item.get("status") == "COMPLETED" and item.get("report")]
    failed = [item for item in results if item not in completed]
    summary = st.container(horizontal=True)
    with summary:
        st.metric("Selected domains", len(results), border=True)
        st.metric("Reports retrieved", len(completed), border=True)
        st.metric("Unavailable", len(failed), border=True)
        st.metric("Malicious verdicts", sum((item["report"].get("analysis_stats") or {}).get("malicious", 0) for item in completed), border=True)

    st.download_button(
        ":material/download: Download combined DOCX report",
        data=build_batch_docx(batch),
        file_name=f"{batch['id']}_{(batch.get('brand') or 'selected-domains').replace(' ', '-')}_virustotal_report.docx",
        mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        key=f"vt_batch_docx_{batch['id']}",
    )

    rows = []
    for item in results:
        report = item.get("report") or {}
        stats = report.get("analysis_stats") or {}
        rows.append({
            "Domain": item["domain"], "Status": item.get("status"),
            "Malicious": stats.get("malicious", 0), "Suspicious": stats.get("suspicious", 0),
            "Harmless": stats.get("harmless", 0), "Undetected": stats.get("undetected", 0),
            "Reputation": report.get("reputation"), "Error": item.get("error"),
            "VirusTotal": report.get("permalink"),
        })
    st.dataframe(pd.DataFrame(rows), hide_index=True, column_config={"VirusTotal": st.column_config.LinkColumn("VirusTotal report")})

    if completed:
        st.header("Domain intelligence", icon=":material/language:")
        domain_options = {item["domain"]: item for item in completed}
        selected_domain = st.selectbox(
            "Domain to inspect",
            list(domain_options),
            key=f"vt_domain_{batch['id']}",
        )
        selected_item = domain_options[selected_domain]
        report = expand_stored_report(selected_item["report"])
        stats = report.get("analysis_stats") or {}

        with st.container(border=True):
            st.subheader(selected_domain)
            if stats.get("malicious", 0) or stats.get("suspicious", 0):
                st.warning(
                    f"{stats.get('malicious', 0)} malicious and {stats.get('suspicious', 0)} suspicious verdicts were returned.",
                    icon=":material/warning:",
                )
            else:
                st.success(
                    "No security vendor flagged this target as malicious or suspicious in the stored analysis.",
                    icon=":material/check_circle:",
                )
            st.caption(
                f"Last analysis: {format_ist(report.get('last_analysis_date'))} · "
                f"Retrieved: {format_ist(report.get('retrieved_at') or batch.get('retrieved_at'))}"
            )
            st.link_button(
                "Open in VirusTotal",
                report["permalink"],
                icon=":material/open_in_new:",
            )

        detection_tab, details_tab, relations_tab, community_tab = st.tabs([
            ":material/security: Detection",
            ":material/info: Details",
            ":material/hub: Relations",
            ":material/forum: Community",
        ])
        with detection_tab:
            _render_detection(report)
        with details_tab:
            _render_details(report)
        with relations_tab:
            _render_relations(report)
        with community_tab:
            _render_community(report)

    st.caption("VirusTotal combines third-party engine verdicts. A clean or undetected result is not proof that a domain is safe.")
