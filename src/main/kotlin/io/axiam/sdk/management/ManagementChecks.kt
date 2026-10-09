package io.axiam.sdk.management

import io.axiam.sdk.errors.ValidationError
import io.axiam.sdk.management.models.ParseSamlSpMetadata

/**
 * Local checks a generated operation runs before any I/O — the generator's
 * `PRECHECKS` table names them per operation.
 *
 * Each refuses with a [ValidationError] (the SDK's local-refusal mapping) and
 * no request is built.
 */
internal object ManagementChecks {

    /**
     * `saml.parse_sp_metadata` takes **exactly one** of `metadata_xml` and
     * `metadata_url` (CONTRACT.md §29.2); both or neither is refused locally.
     * `ParseSamlSpMetadata.fromUrl` / `fromXml` build only the valid shapes.
     *
     * @param operation the canonical operation name, for the message
     * @param body the request body
     */
    fun parseSpMetadataExactlyOne(operation: String, body: ParseSamlSpMetadata) {
        if ((body.metadataUrl == null) == (body.metadataXml == null)) {
            throw ValidationError(
                "$operation: exactly one of metadata_xml and metadata_url must be set " +
                    "(CONTRACT.md §29.2); this call was refused locally and never reached the network",
            )
        }
    }
}
