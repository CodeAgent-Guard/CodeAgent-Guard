import { describe, expect, it } from "vitest";
import { formatDate } from "../src/utils/formatDate";

describe("formatDate", () => {
  it("formats ISO dates as yyyy-mm-dd", () => {
    expect(formatDate("2026-07-03T08:30:00.000Z")).toBe("2026-07-03");
  });
});

