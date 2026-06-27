package com.sn1persecurity.silentchain.bapp.export;

import com.sn1persecurity.silentchain.bapp.state.FindingRow;
import com.sn1persecurity.silentchain.bapp.state.FindingsRegistry;

import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.Component;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Exports the findings table to CSV. Ported from Community {@code exportCsv()}
 * (silentchain_ai_community.py:966-1004): header
 * "Discovered At,URL,Finding,Severity,Confidence", default file name
 * SILENTCHAIN_Findings_YYYYMMDD_HHMMSS.csv.
 */
public final class CsvExporter {

    private static final DateTimeFormatter FILE_TS = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");

    private CsvExporter() {}

    /**
     * Show a save dialog and write the findings. Returns the written file path,
     * or null if the user cancelled or there was nothing to write.
     */
    public static String export(Component parent, FindingsRegistry registry) {
        List<FindingRow> rows = registry.snapshot();

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export SILENTCHAIN findings to CSV");
        chooser.setFileFilter(new FileNameExtensionFilter("CSV files (*.csv)", "csv"));
        String defaultName = "SILENTCHAIN_Findings_" + LocalDateTime.now().format(FILE_TS) + ".csv";
        chooser.setSelectedFile(new File(defaultName));

        int result = chooser.showSaveDialog(parent);
        if (result != JFileChooser.APPROVE_OPTION) {
            return null;
        }

        File file = chooser.getSelectedFile();
        if (!file.getName().toLowerCase().endsWith(".csv")) {
            file = new File(file.getParentFile(), file.getName() + ".csv");
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Discovered At,URL,Finding,Severity,Confidence\n");
        for (FindingRow r : rows) {
            sb.append(escape(r.discoveredAt())).append(',')
              .append(escape(r.url())).append(',')
              .append(escape(r.finding())).append(',')
              .append(escape(r.severity())).append(',')
              .append(escape(r.confidence())).append('\n');
        }

        try {
            Files.write(file.toPath(), sb.toString().getBytes(StandardCharsets.UTF_8));
            return file.getAbsolutePath();
        } catch (IOException e) {
            return null;
        }
    }

    private static String escape(String field) {
        if (field == null) {
            return "";
        }
        boolean needsQuoting = field.contains(",") || field.contains("\"")
                || field.contains("\n") || field.contains("\r");
        String escaped = field.replace("\"", "\"\"");
        return needsQuoting ? "\"" + escaped + "\"" : escaped;
    }
}
