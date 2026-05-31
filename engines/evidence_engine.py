"""Evidence collection and chain of custody engine for forensics/pentests."""

import os
import hashlib
import zipfile
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from core.database import generate_id, utc_now


class EvidenceEngine:
    """Engine for evidence collection and chain of custody management."""

    def __init__(self, db, config: dict = None):
        """Initialize the evidence engine.

        Args:
            db: Database instance
            config: Configuration dictionary
        """
        self.db = db
        self.config = (config or {}).get("engines", {}).get("evidence", {})

        # Evidence storage directory
        self.base_path = Path(self.config.get("storage_path", "data/evidence"))
        self.base_path.mkdir(parents=True, exist_ok=True)

        # In-memory storage for evidence metadata (since we're not modifying DB schema)
        self.evidence_registry = {}
        self.custody_chains = {}

        # Supported evidence types
        self.evidence_types = [
            "screenshot",
            "packet_capture",
            "log_file",
            "command_output",
            "configuration",
            "credential",
            "exploit_output",
            "memory_dump",
            "disk_image",
            "network_traffic",
            "malware_sample",
            "other"
        ]

    async def collect_evidence(
        self,
        evidence_type: str,
        description: str,
        source: str,
        data: Any,
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Store evidence with hash integrity.

        Args:
            evidence_type: Type of evidence (screenshot, packet_capture, etc.)
            description: Description of the evidence
            source: Source of the evidence (hostname, IP, tool name, etc.)
            data: Evidence data (file path, bytes, or string)
            project_id: Project ID
            target_id: Optional target ID

        Returns:
            Dictionary with evidence metadata
        """
        try:
            if evidence_type not in self.evidence_types:
                return {
                    "success": False,
                    "error": f"Invalid evidence type. Must be one of: {', '.join(self.evidence_types)}"
                }

            # Generate evidence ID
            evidence_id = generate_id()

            # Create project directory
            project_dir = self.base_path / project_id
            project_dir.mkdir(parents=True, exist_ok=True)

            # Determine file extension and process data
            file_ext = self._get_file_extension(evidence_type, data)
            evidence_filename = f"{evidence_id}{file_ext}"
            evidence_path = project_dir / evidence_filename

            # Write evidence to file
            if isinstance(data, (str, bytes)):
                mode = 'wb' if isinstance(data, bytes) else 'w'
                with open(evidence_path, mode) as f:
                    f.write(data)
            elif isinstance(data, Path) or (isinstance(data, str) and os.path.exists(data)):
                # Copy file if data is a path
                import shutil
                shutil.copy2(data, evidence_path)
            else:
                # Serialize as JSON for complex objects
                with open(evidence_path, 'w') as f:
                    json.dump(data, f, indent=2)

            # Calculate SHA256 hash
            evidence_hash = self._calculate_hash(evidence_path)

            # Get file size
            file_size = evidence_path.stat().st_size

            # Create evidence metadata
            evidence_metadata = {
                "id": evidence_id,
                "type": evidence_type,
                "description": description,
                "source": source,
                "project_id": project_id,
                "target_id": target_id,
                "filename": evidence_filename,
                "file_path": str(evidence_path),
                "file_size": file_size,
                "sha256_hash": evidence_hash,
                "collected_at": utc_now(),
                "collected_by": "system",
                "integrity_verified": True
            }

            # Store in registry
            self.evidence_registry[evidence_id] = evidence_metadata

            # Create initial chain of custody entry
            await self.create_custody_entry(
                evidence_id=evidence_id,
                action="collected",
                handler="system",
                notes=f"Evidence collected: {description}"
            )

            # Audit log
            await self.db.audit(
                action="collect_evidence",
                resource_type="evidence",
                resource_id=evidence_id,
                details={
                    "project_id": project_id,
                    "target_id": target_id,
                    "type": evidence_type,
                    "size": file_size,
                    "hash": evidence_hash
                },
                severity="info"
            )

            return {
                "success": True,
                "evidence_id": evidence_id,
                "file_path": str(evidence_path),
                "sha256_hash": evidence_hash,
                "file_size": file_size,
                "metadata": evidence_metadata
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def list_evidence(self, project_id: str = None, target_id: str = None) -> Dict[str, Any]:
        """List all evidence for a project with metadata.

        Args:
            project_id: Project ID
            target_id: Optional target ID to filter by

        Returns:
            Dictionary with evidence list
        """
        try:
            # Filter evidence by project and optionally target
            evidence_list = []

            for evidence_id, metadata in self.evidence_registry.items():
                if metadata.get("project_id") == project_id:
                    if target_id is None or metadata.get("target_id") == target_id:
                        # Verify integrity
                        is_valid = self._verify_file_integrity(
                            metadata["file_path"],
                            metadata["sha256_hash"]
                        )

                        evidence_list.append({
                            **metadata,
                            "integrity_verified": is_valid,
                            "integrity_status": "valid" if is_valid else "COMPROMISED"
                        })

            # Sort by collection time
            evidence_list.sort(key=lambda x: x.get("collected_at", ""), reverse=True)

            # Group by type
            by_type = {}
            for evidence in evidence_list:
                etype = evidence["type"]
                if etype not in by_type:
                    by_type[etype] = []
                by_type[etype].append(evidence)

            return {
                "success": True,
                "evidence": evidence_list,
                "total_count": len(evidence_list),
                "by_type": {k: len(v) for k, v in by_type.items()},
                "total_size": sum(e["file_size"] for e in evidence_list)
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def get_evidence(self, evidence_id: str, project_id: str = None, target_id: str = None) -> Dict[str, Any]:
        """Retrieve evidence with integrity verification.

        Args:
            evidence_id: Evidence ID
            project_id: Project ID
            target_id: Optional target ID

        Returns:
            Dictionary with evidence data
        """
        try:
            # Get metadata
            metadata = self.evidence_registry.get(evidence_id)

            if not metadata:
                return {
                    "success": False,
                    "error": "Evidence not found"
                }

            # Verify integrity
            integrity_result = await self.verify_integrity(evidence_id)

            if not integrity_result["success"]:
                return integrity_result

            # Get custody chain
            custody_chain = await self.get_custody_chain(evidence_id)

            # Log access
            await self.create_custody_entry(
                evidence_id=evidence_id,
                action="accessed",
                handler="system",
                notes="Evidence retrieved for review"
            )

            return {
                "success": True,
                "evidence_id": evidence_id,
                "metadata": metadata,
                "integrity_status": integrity_result["status"],
                "custody_chain": custody_chain.get("chain", [])
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def verify_integrity(self, evidence_id: str, project_id: str = None, target_id: str = None) -> Dict[str, Any]:
        """Verify evidence hasn't been tampered with.

        Args:
            evidence_id: Evidence ID
            project_id: Project ID
            target_id: Optional target ID

        Returns:
            Dictionary with verification results
        """
        try:
            # Get metadata
            metadata = self.evidence_registry.get(evidence_id)

            if not metadata:
                return {
                    "success": False,
                    "error": "Evidence not found"
                }

            file_path = metadata["file_path"]
            original_hash = metadata["sha256_hash"]

            # Check if file still exists
            if not os.path.exists(file_path):
                return {
                    "success": False,
                    "status": "missing",
                    "error": "Evidence file not found",
                    "original_hash": original_hash
                }

            # Recalculate hash
            current_hash = self._calculate_hash(file_path)

            # Compare hashes
            is_valid = current_hash == original_hash

            # Update metadata
            metadata["integrity_verified"] = is_valid
            metadata["last_verified_at"] = utc_now()

            # Log verification
            await self.db.audit(
                action="verify_evidence_integrity",
                resource_type="evidence",
                resource_id=evidence_id,
                details={
                    "is_valid": is_valid,
                    "original_hash": original_hash,
                    "current_hash": current_hash
                },
                severity="warning" if not is_valid else "info"
            )

            if not is_valid:
                # Create custody entry for tampering
                await self.create_custody_entry(
                    evidence_id=evidence_id,
                    action="integrity_violation",
                    handler="system",
                    notes="CRITICAL: Evidence integrity check FAILED - possible tampering detected"
                )

            return {
                "success": True,
                "status": "valid" if is_valid else "COMPROMISED",
                "is_valid": is_valid,
                "original_hash": original_hash,
                "current_hash": current_hash,
                "verified_at": utc_now()
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def create_custody_entry(
        self,
        evidence_id: str,
        action: str,
        handler: str,
        notes: str = "",
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Log a chain of custody entry.

        Args:
            evidence_id: Evidence ID
            action: Action taken (collected, transferred, analyzed, presented, archived)
            handler: Person or system handling the evidence
            notes: Additional notes
            project_id: Project ID
            target_id: Optional target ID

        Returns:
            Dictionary with entry confirmation
        """
        try:
            # Create custody entry
            entry = {
                "entry_id": generate_id(),
                "evidence_id": evidence_id,
                "action": action,
                "handler": handler,
                "notes": notes,
                "timestamp": utc_now()
            }

            # Add to chain
            if evidence_id not in self.custody_chains:
                self.custody_chains[evidence_id] = []

            self.custody_chains[evidence_id].append(entry)

            # Audit log
            await self.db.audit(
                action="custody_entry",
                resource_type="evidence",
                resource_id=evidence_id,
                details={
                    "custody_action": action,
                    "handler": handler,
                    "entry_id": entry["entry_id"]
                },
                severity="info"
            )

            return {
                "success": True,
                "entry_id": entry["entry_id"],
                "entry": entry
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def get_custody_chain(self, evidence_id: str, project_id: str = None, target_id: str = None) -> Dict[str, Any]:
        """Get full chain of custody for an evidence item.

        Args:
            evidence_id: Evidence ID
            project_id: Project ID
            target_id: Optional target ID

        Returns:
            Dictionary with custody chain
        """
        try:
            # Get chain
            chain = self.custody_chains.get(evidence_id, [])

            # Sort by timestamp
            chain.sort(key=lambda x: x.get("timestamp", ""))

            return {
                "success": True,
                "evidence_id": evidence_id,
                "chain": chain,
                "total_entries": len(chain),
                "first_entry": chain[0] if chain else None,
                "last_entry": chain[-1] if chain else None
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def export_evidence_package(
        self,
        project_id: str,
        output_path: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Export all evidence for a project as a ZIP with manifest.

        Args:
            project_id: Project ID
            output_path: Optional output path for ZIP file
            target_id: Optional target ID to filter by

        Returns:
            Dictionary with export results
        """
        try:
            # Get all evidence for project
            evidence_result = await self.list_evidence(project_id, target_id)

            if not evidence_result["success"]:
                return evidence_result

            evidence_list = evidence_result["evidence"]

            if not evidence_list:
                return {
                    "success": False,
                    "error": "No evidence found for project"
                }

            # Determine output path
            if not output_path:
                output_path = self.base_path / f"{project_id}_evidence_package.zip"
            else:
                output_path = Path(output_path)

            # Create manifest
            manifest = {
                "project_id": project_id,
                "target_id": target_id,
                "exported_at": utc_now(),
                "total_items": len(evidence_list),
                "evidence": []
            }

            # Create ZIP file
            with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for evidence in evidence_list:
                    evidence_id = evidence["id"]
                    file_path = Path(evidence["file_path"])

                    if file_path.exists():
                        # Add file to ZIP
                        arcname = f"{evidence_id}_{file_path.name}"
                        zipf.write(file_path, arcname)

                        # Get custody chain
                        custody = await self.get_custody_chain(evidence_id)

                        # Add to manifest
                        manifest["evidence"].append({
                            "evidence_id": evidence_id,
                            "type": evidence["type"],
                            "description": evidence["description"],
                            "source": evidence["source"],
                            "filename": arcname,
                            "sha256_hash": evidence["sha256_hash"],
                            "file_size": evidence["file_size"],
                            "collected_at": evidence["collected_at"],
                            "integrity_status": evidence.get("integrity_status", "unknown"),
                            "custody_entries": len(custody.get("chain", []))
                        })

                        # Add custody chain as JSON
                        custody_filename = f"{evidence_id}_custody.json"
                        zipf.writestr(custody_filename, json.dumps(custody.get("chain", []), indent=2))

                # Add manifest
                zipf.writestr("MANIFEST.json", json.dumps(manifest, indent=2))

                # Add integrity file with all hashes
                integrity_data = {
                    "project_id": project_id,
                    "generated_at": utc_now(),
                    "evidence_hashes": {
                        e["evidence_id"]: e["sha256_hash"]
                        for e in manifest["evidence"]
                    }
                }
                zipf.writestr("INTEGRITY.json", json.dumps(integrity_data, indent=2))

            # Get package size
            package_size = output_path.stat().st_size

            # Audit log
            await self.db.audit(
                action="export_evidence_package",
                resource_type="evidence",
                resource_id=project_id,
                details={
                    "project_id": project_id,
                    "items_exported": len(evidence_list),
                    "package_size": package_size,
                    "output_path": str(output_path)
                },
                severity="info"
            )

            return {
                "success": True,
                "package_path": str(output_path),
                "package_size": package_size,
                "items_exported": len(evidence_list),
                "manifest": manifest
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def generate_evidence_report(self, project_id: str = None, target_id: str = None) -> Dict[str, Any]:
        """Generate evidence report with chain of custody documentation.

        Args:
            project_id: Project ID
            target_id: Optional target ID

        Returns:
            Dictionary with report data
        """
        try:
            # Get all evidence
            evidence_result = await self.list_evidence(project_id, target_id)

            if not evidence_result["success"]:
                return evidence_result

            evidence_list = evidence_result["evidence"]

            # Build comprehensive report
            report = {
                "report_id": generate_id(),
                "project_id": project_id,
                "target_id": target_id,
                "generated_at": utc_now(),
                "summary": {
                    "total_items": len(evidence_list),
                    "total_size": evidence_result["total_size"],
                    "by_type": evidence_result["by_type"],
                    "integrity_status": {
                        "valid": len([e for e in evidence_list if e.get("integrity_status") == "valid"]),
                        "compromised": len([e for e in evidence_list if e.get("integrity_status") == "COMPROMISED"]),
                        "unknown": len([e for e in evidence_list if e.get("integrity_status") not in ["valid", "COMPROMISED"]])
                    }
                },
                "evidence_items": []
            }

            # Add detailed evidence items
            for evidence in evidence_list:
                evidence_id = evidence["id"]

                # Get custody chain
                custody_result = await self.get_custody_chain(evidence_id)

                report["evidence_items"].append({
                    "evidence_id": evidence_id,
                    "type": evidence["type"],
                    "description": evidence["description"],
                    "source": evidence["source"],
                    "collected_at": evidence["collected_at"],
                    "file_size": evidence["file_size"],
                    "sha256_hash": evidence["sha256_hash"],
                    "integrity_status": evidence.get("integrity_status", "unknown"),
                    "custody_chain_entries": len(custody_result.get("chain", [])),
                    "custody_chain": custody_result.get("chain", [])
                })

            # Add recommendations
            report["recommendations"] = self._generate_evidence_recommendations(evidence_list)

            # Audit log
            await self.db.audit(
                action="generate_evidence_report",
                resource_type="report",
                resource_id=report["report_id"],
                details={
                    "project_id": project_id,
                    "items_reported": len(evidence_list)
                },
                severity="info"
            )

            return {
                "success": True,
                "report": report
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    # Helper methods

    def _get_file_extension(self, evidence_type: str, data: Any) -> str:
        """Determine file extension based on evidence type and data."""
        extensions = {
            "screenshot": ".png",
            "packet_capture": ".pcap",
            "log_file": ".log",
            "command_output": ".txt",
            "configuration": ".conf",
            "credential": ".txt",
            "exploit_output": ".txt",
            "memory_dump": ".dmp",
            "disk_image": ".img",
            "network_traffic": ".pcap",
            "malware_sample": ".bin",
            "other": ".dat"
        }

        # Check if data is a file path with extension
        if isinstance(data, (str, Path)):
            data_path = Path(data)
            if data_path.exists() and data_path.suffix:
                return data_path.suffix

        return extensions.get(evidence_type, ".dat")

    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file."""
        sha256_hash = hashlib.sha256()

        with open(file_path, "rb") as f:
            # Read in chunks for large files
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)

        return sha256_hash.hexdigest()

    def _verify_file_integrity(self, file_path: str, original_hash: str) -> bool:
        """Verify file integrity by comparing hashes."""
        if not os.path.exists(file_path):
            return False

        current_hash = self._calculate_hash(file_path)
        return current_hash == original_hash

    def _generate_evidence_recommendations(self, evidence_list: List[Dict]) -> List[str]:
        """Generate recommendations based on evidence analysis."""
        recommendations = []

        # Check for compromised evidence
        compromised = [e for e in evidence_list if e.get("integrity_status") == "COMPROMISED"]
        if compromised:
            recommendations.append(
                f"CRITICAL: {len(compromised)} evidence item(s) failed integrity check - investigate immediately"
            )

        # Check for missing custody entries
        sparse_custody = [e for e in evidence_list if e.get("custody_chain_entries", 0) < 2]
        if sparse_custody:
            recommendations.append(
                f"{len(sparse_custody)} evidence item(s) have minimal custody documentation - add detailed handling records"
            )

        # General recommendations
        recommendations.extend([
            "Store evidence package in secure, access-controlled location",
            "Maintain offline backup of evidence with integrity verification",
            "Document all evidence handling in chain of custody",
            "Regular integrity verification recommended (weekly minimum)"
        ])

        return recommendations
