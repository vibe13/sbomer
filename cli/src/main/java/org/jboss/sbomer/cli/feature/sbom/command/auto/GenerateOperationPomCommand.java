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
package org.jboss.sbomer.cli.feature.sbom.command.auto;

import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;

import org.jboss.pnc.dto.DeliverableAnalyzerOperation;
import org.jboss.pnc.dto.ProductMilestone;
import org.jboss.pnc.dto.ProductVersion;
import org.jboss.pnc.dto.response.AnalyzedArtifact;
import org.jboss.sbomer.cli.feature.sbom.command.PathConverter;
import org.jboss.sbomer.cli.feature.sbom.service.PncService;
import org.jboss.sbomer.core.errors.ApplicationException;
import org.jboss.sbomer.core.features.sbom.config.runtime.DeliverableConfig;
import org.jboss.sbomer.core.features.sbom.config.runtime.OperationConfig;
import org.jboss.sbomer.core.features.sbom.enums.GenerationResult;
import org.jboss.sbomer.core.features.sbom.utils.ObjectMapperProvider;
import org.jboss.sbomer.core.features.sbom.utils.maven.MavenPomBuilder;

import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;

import jakarta.inject.Inject;
import lombok.extern.slf4j.Slf4j;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;

/**
 * <p>
 * Command to generate a deliverable pom for SBOMer generation
 * </p>
 */
@Slf4j
@Command(
        mixinStandardHelpOptions = true,
        name = "generate-operation-pom",
        description = "Prepares the deliverable poms for a given PNC operation")
public class GenerateOperationPomCommand implements Callable<Integer> {

    @Option(
            names = { "-c", "--config", },
            paramLabel = "FILE",
            description = "Location of the runtime operation configuration file.",
            required = true)
    Path configPath;

    @Option(
            names = { "--index" },
            description = "Index to select the deliverable configuration passed in the --config option. Starts from 0. If not provided POMs will be generated for every deliverable in the config serially")
    Integer index;

    @Option(
            names = { "--workdir" },
            defaultValue = "workdir",
            paramLabel = "DIR",
            description = "The directory where the generation should be performed. Default: ${DEFAULT-VALUE}",
            converter = PathConverter.class)
    Path workdir;

    @Option(
            names = { "-f", "--force" },
            description = "If the workdir directory should be cleaned up in case it already exists. Default: ${DEFAULT-VALUE}")
    boolean force = false;

    @Spec
    CommandSpec spec;

    ObjectMapper objectMapper = ObjectMapperProvider.yaml();

    @Inject
    PncService pncService;

    /**
     * @return {@code 0} in case the generation process finished successfully, {@code 1} in case a general error
     *         occurred that is not covered by more specific exit code, {@code 2} when a problem related to
     *         configuration file reading or parsing, {@code 3} when the index parameter is incorrect, {@code 4} when
     *         generation process did not finish successfully
     */
    @Override
    public Integer call() throws Exception {

        if (configPath == null) {
            log.info("Configuration path is null, cannot do any generation.");
            return GenerationResult.ERR_CONFIG_MISSING.getCode();
        }

        log.info("Reading configuration file from '{}'", configPath.toAbsolutePath());

        if (!Files.exists(configPath)) {
            log.info("Configuration file '{}' does not exist", configPath.toAbsolutePath());
            return GenerationResult.ERR_CONFIG_MISSING.getCode();
        }

        // It is able to read both: JSON and YAML config files
        OperationConfig config;

        try {
            config = objectMapper.readValue(configPath.toAbsolutePath().toFile(), OperationConfig.class);
        } catch (StreamReadException e) {
            log.error("Unable to parse the configuration file", e);
            return GenerationResult.ERR_CONFIG_INVALID.getCode();
        } catch (DatabindException e) {
            log.error("Unable to deserialize the configuration file", e);
            return GenerationResult.ERR_CONFIG_INVALID.getCode();
        } catch (IOException e) {
            log.error("Unable to read configuration file", e);
            return GenerationResult.ERR_CONFIG_INVALID.getCode();
        }

        log.debug("Configuration read successfully: {}", config);

        List<DeliverableConfig> deliverables = config.getDeliverables();
        if (index != null) {

            if (index < 0) {
                log.error("Provided index '{}' is lower than minimal required: 0", index);
                return GenerationResult.ERR_INDEX_INVALID.getCode();
            }

            if (index >= deliverables.size()) {
                log.error("Provided index '{}' is out of the available range [0-{}]", index, deliverables.size() - 1);
                return GenerationResult.ERR_INDEX_INVALID.getCode();
            }

            log.info("Running POM generation for deliverable with index '{}'", index);

            try {
                generateDeliverablePom(config, deliverables.get(index), index);
            } catch (ApplicationException e) {
                log.error("Generation process failed", e);
                return GenerationResult.ERR_GENERATION.getCode();
            }
        } else {
            log.debug(
                    "Generating POMs for all {} deliverables defined in the runtime configuration",
                    deliverables.size());

            for (int i = 0; i < deliverables.size(); i++) {
                try {
                    generateDeliverablePom(config, deliverables.get(i), i);
                } catch (ApplicationException e) {
                    log.error("Generation process failed", e);
                    return GenerationResult.ERR_GENERATION.getCode();
                }
            }
        }

        return GenerationResult.SUCCESS.getCode();
    }

    private String extractFilenameFromURL(String url) {
        try {
            return Paths.get(new URL(url).getPath()).getFileName().toString();
        } catch (Exception e) {
            return null;
        }
    }

    private void generateDeliverablePom(OperationConfig config, DeliverableConfig deliverable, int i) {
        log.info(
                "Generating deliverable POM for the deliverable: {}, with index: {}, with the provided config: {}",
                deliverable,
                i,
                config);

        // Get all the analyzed artifacts retrieved in the deliverable analyzer operation
        List<AnalyzedArtifact> allAnalyzedArtifacts = pncService.getAllAnalyzedArtifacts(config.getOperationId());
        // A single operation might include multiple archives, filter only the ones related to this particular
        // deliverable
        List<AnalyzedArtifact> currentDeliverableArtifacts = allAnalyzedArtifacts.stream().filter(a -> {
            return deliverable.getUrl().equals(a.getDistribution().getDistributionUrl());
        }).collect(Collectors.toList());

        log.info(
                "Retrieved {} artifacts in the specified deliverable: '{}', out of {} total analyzed artifacts in the operation: '{}'",
                currentDeliverableArtifacts.size(),
                deliverable.getUrl(),
                allAnalyzedArtifacts.size(),
                config.getOperationId());

        // Exclude from the analyzed artifacts' filenames the filenames related to exploded locations (e.g. inside jars)
        List<AnalyzedArtifact> nonNestedArtifacts = currentDeliverableArtifacts.stream().filter(a -> {
            List<String> filenames = a.getArchiveFilenames();
            filenames.removeIf(filename -> filename.contains(".jar!/"));
            return filenames.size() > 0;
        }).collect(Collectors.toList());

        String groupId = "groupId";
        String artifactId = "artifactId";

        DeliverableAnalyzerOperation operation = pncService.getDeliverableAnalyzerOperation(config.getOperationId());
        if (operation.getProductMilestone() != null) {
            ProductMilestone milestone = pncService.getMilestone(operation.getProductMilestone().getId());
            if (milestone != null && milestone.getProductVersion() != null) {
                ProductVersion productVersion = pncService.getProductVersion(milestone.getProductVersion().getId());
                groupId = productVersion.getProduct().getName().replace(" ", "-").toLowerCase();
                artifactId = milestone.getVersion();
            }
        }

        String fileName = extractFilenameFromURL(deliverable.getUrl());

        MavenPomBuilder mavenPomBuilder = MavenPomBuilder.build()
                .createModel(
                        groupId,
                        artifactId,
                        fileName,
                        "POM representing the deliverable " + fileName + " analyzed with operation "
                                + config.getOperationId());

        nonNestedArtifacts.forEach(a -> {
            try {
                PackageURL packageURL = new PackageURL(a.getArtifact().getPurl());
                if ("maven".equals(packageURL.getType())) {

                    String classifier = null;
                    String type = null;
                    if (packageURL.getQualifiers() != null) {
                        classifier = packageURL.getQualifiers().get("classifier");
                        type = packageURL.getQualifiers().get("type");
                    }

                    mavenPomBuilder.addDependency(
                            packageURL.getNamespace(),
                            packageURL.getName(),
                            packageURL.getVersion(),
                            type,
                            classifier,
                            a.getArtifact().getId());
                }
            } catch (MalformedPackageURLException e) {
                log.info("Could not parse the purl {}", a.getArtifact().getPurl());
            }
        });

        try {
            String pomFilename = workdir.getFileName().toString() + "-pom.xml";
            Path pomPath = Path.of(Paths.get("").toAbsolutePath().toString(), pomFilename);
            mavenPomBuilder.writePomFile(pomPath);
        } catch (IOException e) {
            throw new ApplicationException("Could not write the pom for the deliverable: '{}'", deliverable.getUrl());
        }
    }
}
