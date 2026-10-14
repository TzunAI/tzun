"""Catalog library layer — policy + row construction over the
storage primitives. Mirrors TS src/models/annotations.ts (admin gate at the
library, never the adapter) and src/api/models-routes.ts walkLineage.
Named catalog.py, not models/, because tzun_sdk.models is the wire-models module.

The admin gate rule (from TS annotations.ts):
  - ``freeform-note`` → no admin gate
  - any other type   → admin gate enforced (raises AdminTokenRequiredError)
  Unknown / custom annotation types are admin-gated and stored as-is;
  the enriched-view builder ignores them.
"""
from __future__ import annotations

import json
import uuid
from typing import Any

from tzun_sdk.errors import AdminTokenRequiredError
from tzun_sdk.models import ModelDescriptorAnnotationRow, ModelLineageEntry

FREEFORM_NOTE = "freeform-note"
MAX_LINEAGE_DEPTH = 16


def _utcnow_iso() -> str:
    import datetime as _dt

    return _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


async def annotate_model_descriptor(
    storage: Any,
    digest: str,
    annotation_type: str,
    value: dict[str, Any],
    *,
    is_admin: bool = False,
    annotated_by: str,
    note: str | None = None,
    signature: str | None = None,
) -> ModelDescriptorAnnotationRow:
    """Build and append a ModelDescriptorAnnotationRow.

    Admin gate (mirrors TS annotations.ts:98-103):
      - ``freeform-note`` → no admin required (is_admin may be False)
      - any other type   → is_admin MUST be True or AdminTokenRequiredError raised

    Value serialization: ``value`` (dict) is JSON-serialized to ``valueJson`` string.
    For ``retract`` annotations, ``value.retractsAnnotationId`` is mirrored to the
    ``retractsAnnotationId`` column (mirrors TS annotations.ts:138).
    """
    if annotation_type != FREEFORM_NOTE and not is_admin:
        raise AdminTokenRequiredError(
            f"annotation type '{annotation_type}' requires admin auth. "
            "Only 'freeform-note' may be created without admin."
        )
    # For retraction, mirror the retractsAnnotationId onto the dedicated column
    retracts_annotation_id: str | None = None
    if annotation_type == "retract":
        retracts_annotation_id = str(value.get("retractsAnnotationId", "")) or None

    row = ModelDescriptorAnnotationRow(
        annotationId=str(uuid.uuid4()),
        modelDescriptorDigest=digest,
        annotationType=annotation_type,
        valueJson=json.dumps(value),
        annotatedBy=annotated_by,
        annotatedAt=_utcnow_iso(),
        retractsAnnotationId=retracts_annotation_id,
        note=note,
        signature=signature,
    )
    await storage.append_model_descriptor_annotation(row)
    return row


async def walk_lineage(
    storage: Any, leaf_digest: str
) -> list[ModelLineageEntry] | None:
    """Leaf→root parent-DAG walk: depth cap 16, partial-on-missing-ancestor,
    None for an unknown leaf digest — mirrors models-routes.ts:76-127 semantics.

    Returns:
        - ``None`` if the leaf digest is not found in storage
        - ``list[ModelLineageEntry]`` in leaf→root order (partial is OK when an
          ancestor is missing from storage)
    """
    leaf = await storage.get_descriptor(leaf_digest)
    if leaf is None:
        return None

    def entry(digest: str, d: Any) -> ModelLineageEntry:
        return ModelLineageEntry(
            descriptorDigest=digest,
            integrityTier=d.integrityTier,
            derivation=d.derivation,
            trainedBy=d.trainedBy,
        )

    lineage = [entry(leaf_digest, leaf)]
    visited = {leaf_digest}
    current = leaf
    while len(lineage) < MAX_LINEAGE_DEPTH:
        parent_digest = current.parentModelDescriptorDigest
        if parent_digest is None or parent_digest in visited:
            break
        parent = await storage.get_descriptor(parent_digest)
        if parent is None:
            break  # partial lineage is meaningful — do not raise
        lineage.append(entry(parent_digest, parent))
        visited.add(parent_digest)
        current = parent
    return lineage
