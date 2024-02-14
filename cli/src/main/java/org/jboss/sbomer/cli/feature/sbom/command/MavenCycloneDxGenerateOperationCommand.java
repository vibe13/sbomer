/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jboss.sbomer.cli.feature.sbom.command;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.apache.maven.model.Dependency;
import org.apache.maven.model.Model;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.jboss.sbomer.core.errors.ApplicationException;
import org.jboss.sbomer.core.features.sbom.enums.GeneratorType;
import org.jboss.sbomer.core.features.sbom.utils.SbomUtils;
import org.jboss.sbomer.core.features.sbom.utils.maven.MavenPomBuilder;

import com.github.packageurl.PackageURL;

import io.quarkus.bootstrap.devmode.DependenciesFilter;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.ScopeType;

@Slf4j
@Command(
        mixinStandardHelpOptions = true,
        name = "maven-cyclonedx-plugin-operation",
        aliases = { "maven-cyclonedx-operation" },
        description = "SBOM generation for deliverable Maven POMs using the CycloneDX Maven plugin"
// , subcommands = { ProcessCommand.class }
)
public class MavenCycloneDxGenerateOperationCommand extends AbstractGenerateOperationCommand {

    @Getter
    @Option(
            names = { "-s", "--settings" },
            description = "Path to Maven settings.xml file that should be used for this run instead of the default one",
            converter = PathConverter.class,
            defaultValue = "${env:SBOMER_MAVEN_SETTINGS_XML_PATH}",
            scope = ScopeType.INHERIT)
    Path settingsXmlPath;

    @Getter
    @Option(
            names = { "--pom" },
            description = "The pom path for which the SBOM needs to be generated.",
            converter = PathConverter.class,
            scope = ScopeType.INHERIT)
    Path pomPath;

    @Getter
    @Option(
            names = { "--workdatadir" },
            description = "The directory where the SBOM should be generated.",
            converter = PathConverter.class,
            scope = ScopeType.INHERIT)
    Path workdatadir;

    @Override
    protected GeneratorType generatorType() {
        return GeneratorType.MAVEN_CYCLONEDX_OPERATION;
    }

    @Override
    protected Path doGenerate() {
        log.info("Generating SBOM for the POM: '{}'", getPomPath().toAbsolutePath());

        // Copy the POM file into its own workdir folder
        Path workingDirPomPath = Path.of(parent.getWorkdir().toAbsolutePath().toString(), "pom.xml");
        copyFile(getPomPath(), workingDirPomPath);

        ProcessBuilder processBuilder = new ProcessBuilder().inheritIO();

        // Split the build command to be passed to the ProcessBuilder, without separating the options surrounded by
        // quotes
        processBuilder.command().add("mvn");
        processBuilder.command().add("-DskipTests=true");
        processBuilder.command()
                .add(String.format("org.cyclonedx:cyclonedx-maven-plugin:%s:makeAggregateBom", toolVersion()));
        processBuilder.command().add("--file");
        processBuilder.command().add(workingDirPomPath.toAbsolutePath().toString());
        processBuilder.command().add("-DoutputFormat=json");
        processBuilder.command().add("-DoutputName=bom");

        if (settingsXmlPath != null) {
            log.debug("Using provided Maven settings.xml configuration file located at '{}'", settingsXmlPath);
            processBuilder.command().add("--settings");
            processBuilder.command().add(settingsXmlPath.toString());
        }

        String args = generatorArgs();
        processBuilder.command().addAll(Arrays.asList(args.split(" ")));

        log.info("Working directory: '{}'", parent.getWorkdir());
        processBuilder.directory(parent.getWorkdir().toFile());

        log.info(
                "Starting SBOM generation using the CycloneDX Maven plugin with command: '{}' ...",
                processBuilder.command().stream().collect(Collectors.joining(" ")));
        Process process = null;

        try {
            process = processBuilder.start();
        } catch (IOException e) {
            throw new ApplicationException("Error while running the command", e);
        }

        int exitCode = -1;

        try {
            exitCode = process.waitFor();
        } catch (InterruptedException e) {
            throw new ApplicationException("Unable to obtain the status for the process", e);
        }

        if (exitCode != 0) {
            throw new ApplicationException("SBOM generation failed, see logs above");
        }

        // Copy the SBOM back to the data folder
        Path sbomWorkingDirPath = Path.of(parent.getWorkdir().toAbsolutePath().toString(), "target", "bom.json");
        Path sbomDataDirPath = Path.of(getPomPath().toAbsolutePath().toString().replace("-pom.xml", "-bom.json"));

        copyFile(sbomWorkingDirPath, sbomDataDirPath);

        Path enhancedSbomDataDirPath = Path
                .of(sbomDataDirPath.toAbsolutePath().toString().replace("-bom.json", "-bom-enhanced.json"));
        adjustGeneratedSbom(sbomDataDirPath, getPomPath(), enhancedSbomDataDirPath);

        return sbomDataDirPath;
    }

    private Path adjustGeneratedSbom(Path bom, Path pom, Path destinationBom) throws ApplicationException {
        log.info(
                "Adjusting any difference between the pom '{}' and the bom '{}'",
                pom.toAbsolutePath(),
                bom.toAbsolutePath());

        Bom sbom = SbomUtils.fromPath(bom);
        if (sbom == null) {
            throw new ApplicationException("Cannot read the generated SBOM '{}'", bom.toAbsolutePath());
        }
        MavenPomBuilder mavenPomBuilder = MavenPomBuilder.build();
        Model model = mavenPomBuilder.readPomFile(pom);
        if (model == null) {
            throw new ApplicationException("Cannot read the created POM '{}'", pom.toAbsolutePath());
        }

        List<Dependency> dependencies = model.getDependencies();
        List<Component> components = sbom.getComponents();
        int depSize = dependencies != null ? dependencies.size() : 0;
        int compSize = components != null ? components.size() : 0;

        if (depSize != compSize) {
            log.info(
                    "The number of components inside the SBOM ({}) is different from the number of dependencies inside the POM ({}), some adjustments need to be made!",
                    compSize,
                    depSize);
            for (int i = 0; i < depSize; i++) {
                Dependency pomDependency = dependencies.get(i);
                PackageURL purl = mavenPomBuilder.getPurlOf(pomDependency);
                if (purl == null) {
                    // Should never happen, but cannot do much about it, if it happens
                    continue;
                }

                Optional<Component> component = SbomUtils.findComponentWithPurl(purl.toString(), sbom);
                if (component.isPresent()) {
                    // The dependency is present as a component in the BOM, cool, let's proceed
                    continue;
                }

                log.info(
                        "The dependency with PURL '{}'' was not found in the generated SBOM, adding it manually!",
                        purl);
                Optional<String> bestMatchingPurl = SbomUtils.findBestMatchingPurl(purl, sbom);
                if (!bestMatchingPurl.isPresent()) {
                    log.warn(
                            "Could not find a best matching PURL for the purl {}, this component cannot be added!",
                            purl);
                    continue;
                }
                Component bestMatchingComponent = SbomUtils.findComponentWithPurl(bestMatchingPurl.get(), sbom).get();
                Component newComponent = SbomUtils.cloneWithPurl(bestMatchingComponent, purl);
                log.info("Adding new cloned component: {}", newComponent);
                sbom.addComponent(newComponent);

                org.cyclonedx.model.Dependency bomNewDependency = new org.cyclonedx.model.Dependency(purl.toString());
                String mainComponentUrl = sbom.getMetadata().getComponent().getBomRef();
                org.cyclonedx.model.Dependency bomMainDependency = null;
                if (sbom.getDependencies() != null) {
                    for (org.cyclonedx.model.Dependency dependency : sbom.getDependencies()) {
                        if (mainComponentUrl.equals(dependency.getRef())) {
                            bomMainDependency = dependency;
                            break;
                        }
                    }
                }
                if (bomMainDependency == null) {
                    bomMainDependency = new org.cyclonedx.model.Dependency(mainComponentUrl);
                }
                bomMainDependency.addDependency(bomNewDependency);
                sbom.addDependency(bomNewDependency);
            }

            // Write the new enhanced SBOM!
            SbomUtils.toPath(sbom, destinationBom);
        }

        // 1) Duplicate multiple versions in the POM into the SBOM, if Missing
        // 2) Fix the main component PURL (using normal url generic PURL)

        return null;
    }

    private void copyFile(Path origin, Path destination) throws ApplicationException {
        try {
            Files.createDirectories(destination);
            Files.copy(origin, destination, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new ApplicationException(
                    "Could not move the POM from '{}' to target location: '{}'",
                    origin,
                    destination,
                    e);
        }
    }

}
