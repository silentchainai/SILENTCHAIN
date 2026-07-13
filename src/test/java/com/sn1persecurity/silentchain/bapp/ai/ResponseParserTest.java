package com.sn1persecurity.silentchain.bapp.ai;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ResponseParserTest {

    /**
     * Regression for the Ollama/Mistral "no findings" bug: with {@code format: json} the model
     * wraps the array under a "findings" key instead of returning a bare array. The three
     * findings below are the real captured output from a scan of testfire.net/search.jsp.
     */
    @Test
    void parsesObjectWrappedFindingsArray() {
        String wrapped = "{\"findings\":["
                + "{\"title\":\"Reflected Cross-Site Scripting (XSS)\",\"severity\":\"High\",\"confidence\":90,"
                + "\"cwe\":\"CWE-79\",\"owasp\":\"A03:2021\",\"detail\":\"Reflected input.\",\"evidence\":\"query\",\"remediation\":\"Encode output.\"},"
                + "{\"title\":\"Server Header Disclosure\",\"severity\":\"Medium\",\"confidence\":75,"
                + "\"cwe\":\"CWE-200\",\"owasp\":\"A05:2021\",\"detail\":\"Server header.\",\"evidence\":\"Apache-Coyote/1.1\",\"remediation\":\"Strip header.\"},"
                + "{\"title\":\"Upgrade Insecure Requests\",\"severity\":\"Low\",\"confidence\":50,"
                + "\"cwe\":\"CWE-295\",\"owasp\":\"A05:2021\",\"detail\":\"UIR header.\",\"evidence\":\"Upgrade-Insecure-Requests: 1\",\"remediation\":\"n/a\"}"
                + "]}";

        List<ParsedFinding> out = ResponseParser.parse(wrapped);

        assertEquals(3, out.size());
        assertEquals("Reflected Cross-Site Scripting (XSS)", out.get(0).title());
        assertEquals("Server Header Disclosure", out.get(1).title());
        assertEquals("Upgrade Insecure Requests", out.get(2).title());
    }

    @Test
    void parsesBareArray() {
        String arr = "[{\"title\":\"A\"},{\"title\":\"B\"}]";
        assertEquals(2, ResponseParser.parse(arr).size());
    }

    @Test
    void parsesLoneFindingObject() {
        List<ParsedFinding> out = ResponseParser.parse("{\"title\":\"Only One\",\"severity\":\"Low\"}");
        assertEquals(1, out.size());
        assertEquals("Only One", out.get(0).title());
    }

    /** A genuine finding that happens to contain an array field must not be mistaken for an envelope. */
    @Test
    void loneFindingWithArrayFieldNotUnwrapped() {
        List<ParsedFinding> out = ResponseParser.parse(
                "{\"title\":\"Has refs\",\"references\":[\"https://x\",\"https://y\"]}");
        assertEquals(1, out.size());
        assertEquals("Has refs", out.get(0).title());
    }

    @Test
    void unwrapsWrappedArrayInsideCodeFences() {
        String fenced = "```json\n{\"findings\":[{\"title\":\"Fenced\"}]}\n```";
        assertEquals(1, ResponseParser.parse(fenced).size());
    }

    /** Safety net: no top-level "title" and exactly one array-valued key under an unexpected name. */
    @Test
    void unwrapsUnexpectedSingleArrayKey() {
        List<ParsedFinding> out = ResponseParser.parse("{\"vulns\":[{\"title\":\"Odd Key\"}]}");
        assertEquals(1, out.size());
        assertEquals("Odd Key", out.get(0).title());
    }

    @Test
    void benignInputsYieldNoFindings() {
        assertTrue(ResponseParser.parse("{\"findings\":[]}").isEmpty());
        assertTrue(ResponseParser.parse("[]").isEmpty());
        assertTrue(ResponseParser.parse(null).isEmpty());
        assertTrue(ResponseParser.parse("   ").isEmpty());
    }

    /**
     * Regression for the local-Ollama symptom: under format:"json" a small model emits a bare
     * empty object "{}". It must yield zero findings (title gate drops the wrapped {}), never throw.
     */
    @Test
    void bareEmptyObjectYieldsNoFindings() {
        assertTrue(ResponseParser.parse("{}").isEmpty());
        assertTrue(ResponseParser.parse("  {\n}  ").isEmpty());
        assertTrue(ResponseParser.parse("```json\n{}\n```").isEmpty());
    }

    /**
     * Salvage: a local model can run a field into num_predict and truncate the JSON mid-object.
     * Findings that completed before the cut-off must still be recovered (the unterminated tail
     * object is dropped). Here two findings completed and a third was cut off.
     */
    @Test
    void recoversCompletedFindingsFromTruncatedJson() {
        String truncated = "{\"findings\":["
                + "{\"title\":\"Reflected XSS in 'tfSearch'\",\"severity\":\"High\",\"cwe\":\"CWE-79\"},"
                + "{\"title\":\"Server Version Disclosure\",\"severity\":\"Low\",\"cwe\":\"CWE-200\"},"
                + "{\"title\":\"Open Redirect\",\"severity\":\"Medium\",\"detail\":\"The RetURL parameter "
                + "is used in a redirect without validation and the response keeps repeating the same "
                + "sentence over and over and over and over and over";  // <- cut off mid-string

        List<ParsedFinding> out = ResponseParser.parse(truncated);
        assertEquals(2, out.size());
        assertEquals("Reflected XSS in 'tfSearch'", out.get(0).title());
        assertEquals("Server Version Disclosure", out.get(1).title());
    }
}
