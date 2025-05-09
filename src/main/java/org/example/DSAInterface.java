// DSAInterface.java
package org.example;

import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.ColumnConstraints;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.Priority;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.HashMap;

public class DSAInterface extends Application {
    private DSA dsa = new DSA();
    private byte[] loadedFileBytes = null;

    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage stage) {
        stage.setTitle("Podpis cyfrowy DSA");

        TextArea inputTextArea = new TextArea();
        TextArea signatureArea = new TextArea();
        TextArea resultArea = new TextArea();
        resultArea.setEditable(false);

        TextField pField = new TextField(dsa.p.toString(16));
        TextField qField = new TextField(dsa.q.toString(16));
        TextField gField = new TextField(dsa.g.toString(16));
        TextField xField = new TextField(dsa.x.toString(16));
        TextField yField = new TextField(dsa.y.toString(16));

        Button applyKeysButton = new Button("Zastosuj parametry");
        applyKeysButton.setOnAction(_ -> {
            try {
                dsa.p = new BigInteger(pField.getText(), 16);
                dsa.q = new BigInteger(qField.getText(), 16);
                dsa.g = new BigInteger(gField.getText(), 16);
                if (!xField.getText().isBlank()) {
                    dsa.x = new BigInteger(xField.getText(), 16);
                }
                dsa.y = new BigInteger(yField.getText(), 16);
                resultArea.setText("Parametry zaktualizowane.");
            } catch (Exception e) {
                resultArea.setText("Błąd przy aktualizacji kluczy: " + e.getMessage());
            }
        });

        Button generateKeysButton = new Button("Generuj nowe klucze");
        generateKeysButton.setOnAction(_ -> {
            dsa.generateKeys();
            pField.setText(dsa.p.toString(16));
            qField.setText(dsa.q.toString(16));
            gField.setText(dsa.g.toString(16));
            xField.setText(dsa.x.toString(16));
            yField.setText(dsa.y.toString(16));
            resultArea.setText("Wygenerowano nowe klucze.");
        });

        Button saveKeysButton = new Button("Zapisz parametry");
        saveKeysButton.setOnAction(_ -> {
            try {
                File file = new FileChooser().showSaveDialog(stage);
                if (file != null) {
                    String data = "p=" + pField.getText() + "\n" +
                            "q=" + qField.getText() + "\n" +
                            "g=" + gField.getText() + "\n" +
                            "x=" + xField.getText() + "\n" +
                            "y=" + yField.getText();
                    Files.writeString(file.toPath(), data);
                    resultArea.setText("Parametry zapisane.");
                }
            } catch (Exception e) {
                resultArea.setText("Błąd zapisu: " + e.getMessage());
            }
        });

        Button savePublicKeysButton = new Button("Zapisz publiczne parametry");
        savePublicKeysButton.setOnAction(_ -> {
            try {
                File file = new FileChooser().showSaveDialog(stage);
                if (file != null) {
                    String data = "p=" + pField.getText() + "\n" +
                            "q=" + qField.getText() + "\n" +
                            "g=" + gField.getText() + "\n" +
                            "y=" + yField.getText();
                    Files.writeString(file.toPath(), data);
                    resultArea.setText("Zapisano tylko publiczne parametry.");
                }
            } catch (Exception e) {
                resultArea.setText("Błąd zapisu: " + e.getMessage());
            }
        });

        Button loadKeysButton = new Button("Wczytaj parametry");
        loadKeysButton.setOnAction(_ -> {
            try {
                File file = new FileChooser().showOpenDialog(stage);
                if (file != null) {
                    HashMap<String, String> map = new HashMap<>();
                    for (String line : Files.readAllLines(file.toPath())) {
                        if (line.contains("=")) {
                            String[] parts = line.split("=", 2);
                            map.put(parts[0], parts[1]);
                        }
                    }
                    pField.setText(map.getOrDefault("p", ""));
                    qField.setText(map.getOrDefault("q", ""));
                    gField.setText(map.getOrDefault("g", ""));
                    xField.setText(map.getOrDefault("x", ""));
                    yField.setText(map.getOrDefault("y", ""));
                    applyKeysButton.fire();
                    resultArea.setText("Parametry wczytane.");
                }
            } catch (Exception e) {
                resultArea.setText("Błąd wczytania: " + e.getMessage());
            }
        });

        Button signButton = new Button("Podpisz");
        signButton.setOnAction(_ -> {
            try {
                if (xField.getText().isBlank()) {
                    resultArea.setText("Brak klucza prywatnego – nie można podpisać.");
                    return;
                }
                byte[] data = (loadedFileBytes != null)
                        ? loadedFileBytes
                        : inputTextArea.getText().getBytes(StandardCharsets.UTF_8);
                String signature = dsa.sign(new String(data, StandardCharsets.UTF_8));
                signatureArea.setText(signature);
                resultArea.setText("Podpisano pomyślnie.");
            } catch (Exception e) {
                resultArea.setText("Błąd podpisywania: " + e.getMessage());
            }
        });

        Button verifyButton = new Button("Weryfikuj");
        verifyButton.setOnAction(_ -> {
            try {
                byte[] data = (loadedFileBytes != null)
                        ? loadedFileBytes
                        : inputTextArea.getText().getBytes(StandardCharsets.UTF_8);
                String signature = signatureArea.getText();
                boolean valid = dsa.verify(new String(data, StandardCharsets.UTF_8), signature);
                resultArea.setText(valid ? "Podpis prawidłowy." : "Podpis nieprawidłowy!");
            } catch (Exception e) {
                resultArea.setText("Błąd weryfikacji: " + e.getMessage());
            }
        });

        Button loadFileButton = new Button("Załaduj plik");
        loadFileButton.setOnAction(_ -> {
            try {
                File file = new FileChooser().showOpenDialog(stage);
                if (file != null) {
                    loadedFileBytes = Files.readAllBytes(file.toPath());
                    resultArea.setText("Załadowano plik: " + file.getName());
                }
            } catch (Exception e) {
                resultArea.setText("Błąd odczytu pliku: " + e.getMessage());
            }
        });

        Button saveSignatureButton = new Button("Zapisz podpis");
        saveSignatureButton.setOnAction(_ -> {
            try {
                File file = new FileChooser().showSaveDialog(stage);
                if (file != null) {
                    Files.writeString(file.toPath(), signatureArea.getText());
                    resultArea.setText("Podpis zapisany.");
                }
            } catch (Exception e) {
                resultArea.setText("Błąd zapisu podpisu: " + e.getMessage());
            }
        });

        Button loadSignatureButton = new Button("Wczytaj podpis");
        loadSignatureButton.setOnAction(_ -> {
            try {
                File file = new FileChooser().showOpenDialog(stage);
                if (file != null) {
                    String signature = Files.readString(file.toPath());
                    signatureArea.setText(signature);
                    resultArea.setText("Podpis wczytany.");
                }
            } catch (Exception e) {
                resultArea.setText("Błąd wczytania podpisu: " + e.getMessage());
            }
        });

        GridPane grid = new GridPane();
        grid.setPadding(new Insets(10));
        grid.setVgap(10);
        grid.setHgap(10);

        ColumnConstraints col1 = new ColumnConstraints();
        col1.setPercentWidth(30);
        ColumnConstraints col2 = new ColumnConstraints();
        col2.setPercentWidth(70);
        col2.setHgrow(Priority.ALWAYS);
        grid.getColumnConstraints().addAll(col1, col2);

        grid.add(new Label("Dane tekstowe:"), 0, 0);
        grid.add(inputTextArea, 0, 1, 2, 1);
        grid.add(new Label("Podpis (hex r, s):"), 0, 2);
        grid.add(signatureArea, 0, 3, 2, 1);
        grid.add(signButton, 0, 4);
        grid.add(verifyButton, 1, 4);
        grid.add(loadFileButton, 0, 5);
        grid.add(saveSignatureButton, 1, 5);
        grid.add(loadSignatureButton, 0, 6);

        grid.add(new Label("p (modulus):"), 0, 7);
        grid.add(pField, 1, 7);
        grid.add(new Label("q (prime):"), 0, 8);
        grid.add(qField, 1, 8);
        grid.add(new Label("g (generator):"), 0, 9);
        grid.add(gField, 1, 9);
        grid.add(new Label("x (prywatny):"), 0, 10);
        grid.add(xField, 1, 10);
        grid.add(new Label("y (publiczny):"), 0, 11);
        grid.add(yField, 1, 11);

        grid.add(applyKeysButton, 0, 12);
        grid.add(generateKeysButton, 1, 12);
        grid.add(saveKeysButton, 0, 13);
        grid.add(savePublicKeysButton, 1, 13);
        grid.add(loadKeysButton, 0, 14);
        grid.add(new Label("Wynik:"), 0, 15);
        grid.add(resultArea, 0, 16, 2, 1);

        Scene scene = new Scene(grid, 800, 850);
        stage.setScene(scene);
        stage.show();
    }
}