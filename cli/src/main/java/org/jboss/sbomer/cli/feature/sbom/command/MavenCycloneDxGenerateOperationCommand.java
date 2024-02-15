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

import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.Component.Scope;
import org.cyclonedx.model.Component.Type;
import org.jboss.pnc.enums.BuildType;
import org.jboss.pnc.build.finder.koji.KojiBuild;
import org.jboss.pnc.dto.DeliverableAnalyzerOperation;
import org.jboss.pnc.dto.ProductMilestone;
import org.jboss.pnc.dto.ProductVersion;
import org.jboss.pnc.dto.response.AnalyzedArtifact;
import org.jboss.sbomer.core.errors.ApplicationException;
import org.jboss.sbomer.core.features.sbom.config.runtime.OperationConfig;
import org.jboss.sbomer.core.features.sbom.config.runtime.RedHatProductProcessorConfig;
import org.jboss.sbomer.core.features.sbom.enums.GeneratorType;
import org.jboss.sbomer.core.features.sbom.enums.ProcessorType;
import org.jboss.sbomer.core.features.sbom.utils.ObjectMapperProvider;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import picocli.CommandLine.Command;

import static org.jboss.sbomer.core.features.sbom.Constants.PROPERTY_ERRATA_PRODUCT_NAME;
import static org.jboss.sbomer.core.features.sbom.Constants.PROPERTY_ERRATA_PRODUCT_VARIANT;
import static org.jboss.sbomer.core.features.sbom.Constants.PROPERTY_ERRATA_PRODUCT_VERSION;

import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.addPropertyIfMissing;
import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.createBom;
import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.createComponent;
import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.createDependency;
import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.createMetadata;
import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.setPncBuildMetadata;
import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.setBrewBuildMetadata;
import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.toJsonNode;

@Slf4j
@Command(
        mixinStandardHelpOptions = true,
        name = "maven-cyclonedx-plugin-operation",
        aliases = { "maven-cyclonedx-operation" },
        description = "SBOM generation for deliverable Maven POMs using the CycloneDX Maven plugin")
public class MavenCycloneDxGenerateOperationCommand extends AbstractGenerateOperationCommand {

    ObjectMapper objectMapper = ObjectMapperProvider.yaml();

    @Override
    protected GeneratorType generatorType() {
        return GeneratorType.MAVEN_CYCLONEDX_OPERATION;
    }

    @Override
    protected Path doGenerate() {

        OperationConfig config;

        try {
            config = objectMapper
                    .readValue(getParent().getConfigPath().toAbsolutePath().toFile(), OperationConfig.class);
        } catch (StreamReadException e) {
            log.error("Unable to parse the configuration file", e);
            throw new ApplicationException("Unable to parse the configuration file");
        } catch (DatabindException e) {
            log.error("Unable to deserialize the configuration file", e);
            throw new ApplicationException("Unable to parse the configuration file");
        } catch (IOException e) {
            log.error("Unable to read configuration file", e);
            throw new ApplicationException("Unable to parse the configuration file");
        }

        String deliverableUrl = config.getDeliverableUrls().get(getParent().getIndex());
        log.info(
                "Generating deliverable POM for the deliverable: {}, with index: {}, with the provided config: {}",
                deliverableUrl,
                getParent().getIndex(),
                config);

        // Get all the analyzed artifacts retrieved in the deliverable analyzer operation
        List<AnalyzedArtifact> allAnalyzedArtifacts = pncService.getAllAnalyzedArtifacts(config.getOperationId());
        // A single operation might include multiple archives, filter only the ones related to this particular
        // deliverable
        List<AnalyzedArtifact> currentDeliverableArtifacts = allAnalyzedArtifacts.stream().filter(a -> {
            return deliverableUrl.equals(a.getDistribution().getDistributionUrl());
        }).collect(Collectors.toList());

        log.info(
                "Retrieved {} artifacts in the specified deliverable: '{}', out of {} total analyzed artifacts in the operation: '{}'",
                currentDeliverableArtifacts.size(),
                deliverableUrl,
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

        log.info("Retrieved Product: {}, Milestone: {}", groupId, artifactId);

        String fileName = extractFilenameFromURL(deliverableUrl);
        Bom bom = createBom();
        if (bom == null) {
            throw new ApplicationException("Unable to create a new Bom");
        }

        String mainPurl = "pkg:generic/" + fileName + "@" + artifactId + "?operation=" + getParent().getOperationId();
        String desc = "SBOM representing the deliverable " + fileName + " analyzed with operation "
                + getParent().getOperationId();

        Component mainComponent = createComponent(null, fileName, artifactId, desc, mainPurl, Type.FILE);
        Metadata metadata = createMetadata(mainComponent);
        bom.setMetadata(metadata);
        Dependency mainDependency = createDependency(mainPurl);
        bom.addDependency(mainDependency);

        for (AnalyzedArtifact artifact : nonNestedArtifacts) {

            KojiBuild brewBuild = null;
            BuildType buildType = null;

            if (artifact.getArtifact().getBuild() != null) {
                buildType = artifact.getArtifact().getBuild().getBuildConfigRevision().getBuildType();
            } else if (artifact.getBrewId() != null && artifact.getBrewId() > 0) {
                brewBuild = kojiService.findBuild(artifact.getArtifact());
                buildType = BuildType.MVN;
            }

            if (buildType == null) {
                // While we understand how to represent e.g.
                // 'amq-broker-7.11.5.CR3-bin.zip!/apache-artemis-2.28.0.redhat-00016/web/hawtio.war!/WEB-INF/lib/json-20171018.jar'
                continue;
            }

            Component component = createComponent(artifact.getArtifact(), Scope.REQUIRED, Type.LIBRARY, buildType);

            setPncBuildMetadata(component, artifact.getArtifact().getBuild(), pncService.getApiUrl());

            if (brewBuild != null) {
                setBrewBuildMetadata(
                        component,
                        String.valueOf(brewBuild.getBuildInfo().getId()),
                        brewBuild.getSource(),
                        kojiService.getConfig().getKojiWebURL().toString());
            }

            Dependency dependency = createDependency(artifact.getArtifact().getPurl());
            bom.addComponent(component);
            bom.addDependency(dependency);
            mainDependency.addDependency(dependency);
        }

        if (config.getProduct() != null && config.getProduct().getProcessors() != null) {
            config.getProduct().getProcessors().forEach(processorConfig -> {
                if (ProcessorType.REDHAT_PRODUCT.equals(processorConfig.getType())) {
                    RedHatProductProcessorConfig rhConfig = (RedHatProductProcessorConfig) processorConfig;
                    addPropertyIfMissing(
                            mainComponent,
                            PROPERTY_ERRATA_PRODUCT_NAME,
                            rhConfig.getErrata().getProductName());
                    addPropertyIfMissing(
                            mainComponent,
                            PROPERTY_ERRATA_PRODUCT_VERSION,
                            rhConfig.getErrata().getProductVersion());
                    addPropertyIfMissing(
                            mainComponent,
                            PROPERTY_ERRATA_PRODUCT_VARIANT,
                            rhConfig.getErrata().getProductVariant());
                }
            });
        }

        Path sbomDirPath = Path.of(parent.getWorkdir().toAbsolutePath().toString(), "bom.json");

        try {
            ObjectMapperProvider.json()
                    .writerWithDefaultPrettyPrinter()
                    .writeValue(sbomDirPath.toFile(), toJsonNode(bom));

        } catch (JsonProcessingException e) {
            log.error(e.getMessage(), e);
            throw new ApplicationException("Unable to parse SBOM generated in " + sbomDirPath.toAbsolutePath());
        } catch (IOException e) {
            log.error(e.getMessage(), e);
            throw new ApplicationException("Unable to write the SBOM generated to " + sbomDirPath.toAbsolutePath());
        }

        return sbomDirPath;
    }

    private String extractFilenameFromURL(String url) {
        try {
            return Paths.get(new URI(url).getPath()).getFileName().toString();
        } catch (Exception e) {
            return null;
        }
    }

}
