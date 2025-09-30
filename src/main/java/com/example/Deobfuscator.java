package com.example;

import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;
import weka.classifiers.functions.Logistic;
import weka.core.*;
import javafx.application.Application;
import javafx.stage.Stage;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.FileChooser;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.scene.control.cell.TextFieldTableCell;
import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.jar.*;
import java.util.regex.*;
import java.util.Base64;

public class Deobfuscator extends Application {
    private static final String LOG_FILE = "deobf.log";
    private static final Map<String, String> NAME_MAPPINGS = new HashMap<>();
    private static final Set<String> SUSPECT_METHODS = new HashSet<>();
    private static TextArea logArea;
    private static Logistic mlModel;
    private static File inputJarFile;
    private static File outputJarFile = new File("output_deobf.jar");

    static {
        NAME_MAPPINGS.put("zov", "isCritActive");
        NAME_MAPPINGS.put("pisun", "isAttackActive");
        NAME_MAPPINGS.put("vodka", "targetEntity");
        NAME_MAPPINGS.put("forft", "unusedMethod");
        SUSPECT_METHODS.add("unusedMethod");
    }

    @Override
    public void start(Stage primaryStage) {
        // Инициализация ML-модели
        initializeMLModel();

        // GUI
        BorderPane root = new BorderPane();
        VBox controls = new VBox(10);
        Button selectJarButton = new Button("Выбрать .jar");
        Button deobfButton = new Button("Запустить деобфускацию");
        Button viewLogButton = new Button("Просмотреть лог");
        TableView<Map.Entry<String, String>> mappingTable = new TableView<>();
        TableColumn<Map.Entry<String, String>, String> oldNameCol = new TableColumn<>("Старое имя");
        TableColumn<Map.Entry<String, String>, String> newNameCol = new TableColumn<>("Новое имя");
        oldNameCol.setCellValueFactory(data -> new SimpleStringProperty(data.getValue().getKey()));
        newNameCol.setCellValueFactory(data -> new SimpleStringProperty(data.getValue().getValue()));
        newNameCol.setCellFactory(TextFieldTableCell.forTableColumn());
        newNameCol.setOnEditCommit(event -> {
            Map.Entry<String, String> entry = event.getRowValue();
            NAME_MAPPINGS.put(entry.getKey(), event.getNewValue());
            appendLog("Изменено вручную: " + entry.getKey() + " -> " + event.getNewValue());
        });
        mappingTable.setItems(FXCollections.observableArrayList(NAME_MAPPINGS.entrySet()));
        mappingTable.getColumns().addAll(oldNameCol, newNameCol);
        mappingTable.setEditable(true);
        logArea = new TextArea();
        logArea.setEditable(false);
        controls.getChildren().addAll(selectJarButton, deobfButton, viewLogButton, mappingTable);
        root.setTop(controls);
        root.setCenter(logArea);

        // Действия кнопок
        selectJarButton.setOnAction(e -> {
            FileChooser fileChooser = new FileChooser();
            fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("JAR файлы", "*.jar"));
            inputJarFile = fileChooser.showOpenDialog(primaryStage);
            if (inputJarFile != null) {
                logArea.appendText("Выбран файл: " + inputJarFile.getAbsolutePath() + "\n");
                miniAssistant("Файл " + inputJarFile.getName() + " выбран. Нажмите 'Запустить деобфускацию'.");
            }
        });

        deobfButton.setOnAction(e -> {
            if (inputJarFile != null) {
                new Thread(() -> {
                    try {
                        deobfuscateJar(inputJarFile.getAbsolutePath());
                        logArea.appendText("Деобфускация завершена. Результат в " + outputJarFile.getAbsolutePath() + "\n");
                        miniAssistant("Деобфускация завершена. Проверьте " + outputJarFile.getAbsolutePath() + " и лог в " + LOG_FILE);
                    } catch (Exception ex) {
                        logArea.appendText("Ошибка: " + ex.getMessage() + "\n");
                        miniAssistant("Ошибка деобфускации: " + ex.getMessage() + ". Проверьте файл и попробуйте снова.");
                    }
                }).start();
            } else {
                logArea.appendText("Ошибка: выберите .jar файл\n");
                miniAssistant("Пожалуйста, выберите .jar файл перед запуском.");
            }
        });

        viewLogButton.setOnAction(e -> {
            try (BufferedReader reader = new BufferedReader(new FileReader(LOG_FILE))) {
                logArea.clear();
                String line;
                while ((line = reader.readLine()) != null) {
                    logArea.appendText(line + "\n");
                }
                miniAssistant("Лог загружен. Ищите ошибки или изменения.");
            } catch (IOException ex) {
                logArea.appendText("Ошибка чтения лога: " + ex.getMessage() + "\n");
            }
        });

        Scene scene = new Scene(root, 800, 600);
        primaryStage.setTitle("Деобфускатор JAR");
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    private static void initializeMLModel() {
        try {
            Instances data = new Instances("method_names", new ArrayList<>(), 0);
            data.add(new Attribute("signature"));
            data.add(new Attribute("calls"));
            data.add(new Attribute("name", Arrays.asList("attack", "calculate", "update")));
            data.setClassIndex(2);
            // Пример данных для обучения
            DenseInstance inst1 = new DenseInstance(3);
            inst1.setValue(0, 1.0); // signature
            inst1.setValue(1, 0.0); // calls
            inst1.setClassValue("attack");
            data.add(inst1);

            DenseInstance inst2 = new DenseInstance(3);
            inst2.setValue(0, 0.0);
            inst2.setValue(1, 1.0);
            inst2.setClassValue("calculate");
            data.add(inst2);

            mlModel = new Logistic();
            mlModel.buildClassifier(data);
        } catch (Exception e) {
            logArea.appendText("Ошибка инициализации ML: " + e.getMessage() + "\n");
            miniAssistant("Ошибка в ML-модели. Продолжаем без ML-предсказаний.");
        }
    }

    private static void deobfuscateJar(String inputJar) throws IOException, InterruptedException, ExecutionException {
        appendLog("=== Деобфускация начата: " + new Date() + " ===");

        ExecutorService executor = Executors.newFixedThreadPool(4);
        List<Future<byte[]>> futures = new ArrayList<>();

        try (JarFile jarFile = new JarFile(inputJar);
             JarOutputStream jos = new JarOutputStream(new FileOutputStream(outputJarFile))) {
            Enumeration<JarEntry> entries = jarFile.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.getName().endsWith(".class")) {
                    futures.add(executor.submit(() -> deobfuscateClass(readClass(jarFile, entry), entry.getName())));
                } else {
                    jos.putNextEntry(new JarEntry(entry.getName()));
                    jarFile.getInputStream(entry).transferTo(jos);
                    jos.closeEntry();
                }
            }

            for (Future<byte[]> future : futures) {
                byte[] deobfBytes = future.get();
                Jos.putNextEntry(new JarEntry("deobf_class_" + futures.indexOf(future) + ".class"));
                jos.write(deobfBytes);
                jos.closeEntry();
            }
        }

        executor.shutdown();
        executor.awaitTermination(1, TimeUnit.MINUTES);

        appendLog("=== Деобфускация завершена: " + new Date() + " ===");
    }

    // ... (остальные методы, как в предыдущем коде: readClass, deobfuscateClass, renameFieldsAndMethods, suggestFieldName, predictMethodName, suggestMethodName, deobfuscateString, findDecryptMethod, isJunkMethod, simplifyControlFlow, handleNativeMethods, capitalize)

    private static void appendLog(String message) {
        logArea.appendText(message + "\n");
        try (PrintWriter log = new PrintWriter(new FileWriter(LOG_FILE, true))) {
            log.println(message);
        } catch (IOException e) {
            logArea.appendText("Ошибка записи лога: " + e.getMessage() + "\n");
        }
    }

    private static void miniAssistant(String message) {
        logArea.appendText("Помощник: " + message + "\n");
        if (System.console() != null) {
            System.out.println("Помощник: " + message);
            if (message.endsWith("(y/n)")) {
                String input = SCANNER.nextLine();
                if (input.equalsIgnoreCase("y")) {
                    appendLog("Помощник: Принято имя для " + message.split(":")[1].trim());
                }
            }
        }
    }
}

</xaiArtifact>

### GitHub Actions для билда (`.github/workflows/maven.yml`)
```yml
name: Java CI with Maven

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  build:

    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v2
    - name: Set up JDK 23
      uses: oracle/actions/setup-java@v1
      with:
        java-version: '23'
        distribution: 'oracle'
    - name: Build with Maven
      run: mvn clean package
    - name: Upload artifact
      uses: actions/upload-artifact@v2
      with:
        name: deobfuscator-jar
        path: target/deobfuscator-1.0-SNAPSHOT.jar
