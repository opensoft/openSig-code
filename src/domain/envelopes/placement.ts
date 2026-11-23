// SPDX-License-Identifier: Apache-2.0
//
// Field placement at prepare (T007 follow-up; A-010 requests #46, #49 and #53, row
// T036-RESIDUAL (6)). Prepare refuses, with 422 field_out_of_bounds and detail
// field_too_small, a field the composer could not place. It applies the composer's own
// rule, imported from T036, over the page geometry stored with the document revision,
// so prepare and composition judge a field with ONE function over ONE geometry and
// cannot drift.
//
// The stored geometry is the authority. A revision's stored parse report holds each
// page's number, width, height, rotate, media_box and crop_box (data-model.md §
// Entities, DocumentRevision). The repository reads it (storage/repositories/
// envelopes.ts storedPageGeometry), checks it against the stored displayed geometry
// with the composer's own page-geometry rule, and refuses a missing or inconsistent
// page list as a broken invariant (500 internal, logged). Prepare places from the
// MediaBox and rotation only: never from the PDF, and never from the stored displayed
// width and height, which round to centipoints differently from the MediaBox corners
// (request #49). The call is exactly the composer's (compose.ts, `placeField(page,
// field.rect)` over the page report.ts builds as `{ rotate, box: centipointBox(media) }`):
//
//   placeField({ rotate, box: centipointBox(media_box) }, rect) === null
//     -> field_too_small
//
// Import discipline (request #49 N3). This is the envelope domain's only import from
// src/cryptograph/, and it names appearance.ts and bounds.ts, never compose/index.ts,
// which pulls in the parse service. The runtime closure is five pure modules:
// appearance.ts, bounds.ts (imports nothing), syntax.ts, compose/errors.ts (imports
// nothing) and src/domain/approval/winansi.ts (imports nothing). None reads a file, a
// clock or randomness, starts a process or touches the parse service.

import { placeField } from '../../cryptograph/compose/appearance.ts';
import { centipointBox } from '../../cryptograph/compose/bounds.ts';
// Types only (erased): validation.ts imports this module, so a value import back would be a cycle.
import type { PageGeometry, Rect } from './validation.ts';

/** One page of the stored geometry as placement reads it: its rotation and its MediaBox in points. */
export interface StoredPage {
  readonly rotate: PageGeometry['rotate'];
  readonly media_box: readonly [number, number, number, number];
}

/** Whether the composer can place a field with normalized rectangle `rect` on `page`: its own rule, its own call. */
export function placeable(page: StoredPage, rect: Rect): boolean {
  return placeField({ rotate: page.rotate, box: centipointBox(page.media_box) }, rect) !== null;
}
