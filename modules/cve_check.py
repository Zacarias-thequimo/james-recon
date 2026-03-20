from __future__ import annotations

import httpx

from core.module import BaseModule
from core.target import Target


class CVECheck(BaseModule):
    name = "cve_check"
    description = "Busca de CVEs conhecidas com base nas tecnologias detectadas"

    def enabled(self, target: Target) -> bool:
        return bool(target.technologies) or bool(target.open_ports)

    async def run(self, target: Target) -> Target:
        cves: list[dict] = list(target.cves)
        keywords: set[str] = set()

        for tech, version in target.technologies.items():
            if version and version != "detected":
                keywords.add(f"{tech} {version}")
            else:
                keywords.add(tech)

        for pi in target.open_ports:
            if pi.service and pi.version:
                keywords.add(f"{pi.service} {pi.version}")

        async with httpx.AsyncClient(timeout=15) as client:
            for kw in keywords:
                try:
                    resp = await client.get(
                        "https://cveawg.mitre.org/api/cve",
                        params={"keyword": kw, "resultsPerPage": 5},
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        for item in data.get("vulnerabilities", data.get("cveRecords", []))[:5]:
                            cve_data = item.get("cve", item)
                            cve_id = cve_data.get("id", cve_data.get("cveId", ""))
                            desc_list = cve_data.get("descriptions", [])
                            summary = ""
                            if desc_list:
                                summary = desc_list[0].get("value", "")
                            if cve_id:
                                cves.append({
                                    "id": cve_id,
                                    "keyword": kw,
                                    "summary": summary[:300],
                                })
                except Exception:
                    pass

        target.cves = cves
        return target
