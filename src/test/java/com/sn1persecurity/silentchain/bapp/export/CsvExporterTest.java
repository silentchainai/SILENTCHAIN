package com.sn1persecurity.silentchain.bapp.export;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CsvExporterTest {

    /**
     * Regression for CSV/spreadsheet formula injection in the findings export.
     * Finding titles are LLM-derived and URLs are target-controlled, so either can
     * begin with a formula trigger; every trigger must be prefixed with an
     * apostrophe so the cell is read as text when the customer opens the file.
     */
    @Test
    void prefixesEveryFormulaTrigger() {
        assertEquals("'=cmd|'/C calc'!A1", CsvExporter.escape("=cmd|'/C calc'!A1"));
        assertEquals("'+1+1", CsvExporter.escape("+1+1"));
        assertEquals("'-1+1", CsvExporter.escape("-1+1"));
        assertEquals("'@SUM(A1:A2)", CsvExporter.escape("@SUM(A1:A2)"));
    }

    /**
     * Excel strips a leading tab or CR and then evaluates what follows, so those
     * two must be neutralized as well. A leading CR also forces RFC-4180 quoting,
     * and the apostrophe has to land inside the quotes to have any effect.
     */
    @Test
    void prefixesTabAndCarriageReturnTriggers() {
        assertEquals("'\t=1+1", CsvExporter.escape("\t=1+1"));
        assertEquals("\"'\r=1+1\"", CsvExporter.escape("\r=1+1"));
    }

    /** A trigger character anywhere but the first position is inert. */
    @Test
    void leavesNonLeadingTriggersAlone() {
        assertEquals("SQLi in id=1", CsvExporter.escape("SQLi in id=1"));
        assertEquals("X-Frame-Options", CsvExporter.escape("X-Frame-Options"));
        assertEquals("https://example.com/a?b=c", CsvExporter.escape("https://example.com/a?b=c"));
    }

    /** RFC-4180 quoting still applies, and still applies on top of the prefix. */
    @Test
    void preservesRfc4180Quoting() {
        assertEquals("\"Reflected XSS, unfiltered\"", CsvExporter.escape("Reflected XSS, unfiltered"));
        assertEquals("\"He said \"\"hi\"\"\"", CsvExporter.escape("He said \"hi\""));
        assertEquals("\"line1\nline2\"", CsvExporter.escape("line1\nline2"));

        String out = CsvExporter.escape("=HYPERLINK(\"http://evil\",\"click\")");
        assertTrue(out.startsWith("\"'="), "prefix must sit inside the opening quote: " + out);
        assertTrue(out.contains("\"\"http://evil\"\""), "inner quotes must be doubled: " + out);
    }

    /** Null and empty fields must not produce a stray apostrophe. */
    @Test
    void handlesNullAndEmpty() {
        assertEquals("", CsvExporter.escape(null));
        assertEquals("", CsvExporter.escape(""));
        assertFalse(CsvExporter.escape("").contains("'"));
    }

    /** Ordinary severity and confidence values are untouched. */
    @Test
    void leavesOrdinaryFieldsUnchanged() {
        assertEquals("High", CsvExporter.escape("High"));
        assertEquals("90%", CsvExporter.escape("90%"));
        assertEquals("2026-09-27 11:04:12", CsvExporter.escape("2026-09-27 11:04:12"));
    }
}
