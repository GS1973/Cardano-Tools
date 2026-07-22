// CIP-100 governance-metadata rationale preparation and canonicalization.
//
// The author witness signs the blake2b-256 of the document's `body` field,
// canonicalized with RDF Dataset Canonicalization (URDNA2015). The procedure,
// verified byte-for-byte against the CIP-0100 test vector, is: strip the
// `authors` block (so the body hash does not depend on the signatures being
// produced), canonicalize the whole document, keep the `body` node and its
// descendants, and end the file in a newline.
import * as jsonld from 'jsonld'

export interface RationaleChecks {
  /** A references entry had @type "Link" and was rewritten to "Other". */
  fixedLinkType: boolean
  /** The author name that will carry the witness, for display. */
  authorName: string | null
  /** Blocking problems: the rationale cannot be witnessed until these clear. */
  errors: string[]
}

const ALLOWED_REF_TYPES = ['Other', 'GovernanceMetadata']

/**
 * True when any node under the body carries an explicit `@id`. Canonicalization
 * keeps the body node and its blank-node descendants; a sub-node named by an
 * `@id` IRI is not a blank-node descendant, so its triples would be dropped
 * from the signed bytes. The tool refuses such a body rather than sign a
 * mis-canonicalized one.
 */
function bodyHasIdNode(v: unknown): boolean {
  if (Array.isArray(v)) return v.some(bodyHasIdNode)
  if (v && typeof v === 'object') {
    if ('@id' in (v as Record<string, unknown>)) return true
    return Object.values(v as Record<string, unknown>).some(bodyHasIdNode)
  }
  return false
}

/**
 * Validate a hand-authored rationale against the db-sync render rules and
 * apply the one safe auto-fix (references @type "Link" -> "Other"). Mutates
 * `doc` in place. Returns the checks for display; `errors` non-empty means
 * the document must not be witnessed yet.
 */
export function prepareRationale(doc: any): RationaleChecks {
  const errors: string[] = []
  let fixedLinkType = false
  let authorName: string | null = null

  if (!doc || typeof doc !== 'object') {
    errors.push('file is not a JSON object')
    return { fixedLinkType, authorName, errors }
  }
  if (doc.hashAlgorithm !== 'blake2b-256') {
    errors.push('hashAlgorithm must be "blake2b-256"')
  }
  if (!doc.body || typeof doc.body !== 'object') {
    errors.push('missing a "body" object')
  }

  if (!Array.isArray(doc.authors) || doc.authors.length === 0) {
    errors.push('add an "authors" entry with your name before witnessing')
  } else {
    const a = doc.authors[0]
    authorName = typeof a?.name === 'string' ? a.name : null
    if (!authorName) errors.push('the first author needs a "name"')
  }

  if (doc.body && typeof doc.body === 'object' && bodyHasIdNode(doc.body)) {
    errors.push('body contains an "@id"-identified node, which is not supported (its content would be dropped from the signed body)')
  }

  const refs = doc?.body?.references
  if (Array.isArray(refs)) {
    for (const r of refs) {
      if (r && r['@type'] === 'Link') {
        r['@type'] = 'Other'
        fixedLinkType = true
      }
      if (r && !ALLOWED_REF_TYPES.includes(r['@type'])) {
        errors.push(`reference @type "${r['@type']}" is not allowed (use Other or GovernanceMetadata)`)
      }
    }
  } else if (refs !== undefined && refs !== null) {
    errors.push('body.references must be an array')
  }

  return { fixedLinkType, authorName, errors }
}

/**
 * Produce the CIP-100 canonical body (N-Quads, newline-terminated) whose
 * blake2b-256 the author witness signs. `doc` must already be prepared.
 */
export async function canonicalBody(doc: any): Promise<string> {
  const copy = JSON.parse(JSON.stringify(doc))
  delete copy.authors
  const nquads: string = await (jsonld as any).canonize(copy, {
    algorithm: 'URDNA2015',
    format: 'application/n-quads',
    safe: false,
  })
  const lines = nquads.split('\n').filter((l) => l.length > 0)
  const parsed = lines.map((line) => {
    const m = line.match(/^(\S+)\s+(<[^>]*>)\s+(.*)\s+\.$/)
    if (!m) throw new Error('unexpected N-Quads line: ' + line)
    return { line, subj: m[1], pred: m[2], obj: m[3] }
  })
  const bodyTriple = parsed.find((t) => t.pred.endsWith('#body>'))
  if (!bodyTriple) throw new Error('canonicalized document has no #body node')
  const inSet = new Set<string>([bodyTriple.obj])
  let grew = true
  while (grew) {
    grew = false
    for (const t of parsed) {
      if (inSet.has(t.subj) && t.obj.startsWith('_:') && !inSet.has(t.obj)) {
        inSet.add(t.obj)
        grew = true
      }
    }
  }
  const kept = parsed.filter((t) => t === bodyTriple || inSet.has(t.subj))
  return kept.map((t) => t.line).join('\n') + '\n'
}
