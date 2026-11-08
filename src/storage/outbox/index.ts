// SPDX-License-Identifier: Apache-2.0
//
// Transactional outbox (T030).

export {
  enqueueOutboxEvent,
  OUTBOX_SCHEMA_VERSION,
  WEBHOOK_EVENT_TYPES,
  type EnqueuedOutboxEvent,
  type EnqueueOptions,
  type OutboxEventInput,
  type WebhookEventPayload,
} from './outbox.ts';
export {
  OutboxDispatcher,
  RETRY_HORIZON_MS,
  type DeliveryAttempt,
  type DeliveryResult,
  type DispatcherOptions,
  type DispatchSummary,
} from './dispatcher.ts';
