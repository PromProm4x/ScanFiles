import { createInsertSchema } from "drizzle-zod";
import { index, integer, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm";
import { z } from "zod";

export const scamshieldScansTable = pgTable(
  "scamshield_scans",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    kind: text("kind").notNull(),
    fileName: text("file_name"),
    fileType: text("file_type"),
    target: text("target").notNull(),
    sizeBytes: integer("size_bytes"),
    sha256: text("sha256"),
    sha1: text("sha1"),
    verdict: text("verdict").notNull(),
    indicators: text("indicators")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    detectionSource: text("detection_source").notNull(),
    scannedAt: timestamp("scanned_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index("scamshield_scans_scanned_at_idx").on(table.scannedAt),
    index("scamshield_scans_verdict_idx").on(table.verdict),
    index("scamshield_scans_kind_idx").on(table.kind),
  ],
);

export const insertScamShieldScanSchema = createInsertSchema(
  scamshieldScansTable,
).omit({ id: true, scannedAt: true });

export type InsertScamShieldScan = typeof scamshieldScansTable.$inferInsert;
export type ScamShieldScan = typeof scamshieldScansTable.$inferSelect;
