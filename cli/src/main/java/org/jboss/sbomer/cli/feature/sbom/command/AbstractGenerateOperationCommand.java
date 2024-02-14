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
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicLong;

import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.api.errors.InvalidRemoteException;
import org.jboss.pnc.dto.Build;
import org.jboss.pnc.dto.DeliverableAnalyzerOperation;
import org.jboss.sbomer.cli.feature.sbom.client.facade.SBOMerClientFacade;
import org.jboss.sbomer.cli.feature.sbom.command.mixin.GeneratorToolMixin;
import org.jboss.sbomer.cli.feature.sbom.model.Sbom;
import org.jboss.sbomer.cli.feature.sbom.model.SbomGenerationRequest;
import org.jboss.sbomer.cli.feature.sbom.service.PncService;
import org.jboss.sbomer.core.config.SbomerConfigProvider;
import org.jboss.sbomer.core.config.DefaultGenerationConfig.DefaultGeneratorConfig;
import org.jboss.sbomer.core.errors.ApplicationException;
import org.jboss.sbomer.core.features.sbom.config.runtime.ProductConfig;
import org.jboss.sbomer.core.features.sbom.enums.GeneratorType;
import org.jboss.sbomer.core.features.sbom.utils.MDCUtils;
import org.jboss.sbomer.core.features.sbom.utils.ObjectMapperProvider;
import org.jboss.sbomer.core.features.sbom.utils.SbomUtils;
import org.jboss.sbomer.core.features.sbom.utils.commandline.CommandLineParserUtil;

import com.fasterxml.jackson.databind.JsonNode;

import jakarta.inject.Inject;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import picocli.CommandLine;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.ParentCommand;

@Slf4j
public abstract class AbstractGenerateOperationCommand implements Callable<Integer> {
    @Mixin
    GeneratorToolMixin generator;

    @Getter
    @ParentCommand
    GenerateOperationCommand parent;

    @Inject
    protected PncService pncService;

    @Inject
    protected SBOMerClientFacade sbomerClientFacade;

    protected SbomerConfigProvider sbomerConfigProvider = SbomerConfigProvider.getInstance();

    /**
     * <p>
     * Implementation of the SBOM generation for Maven POMlocated in the {@code parent.getOutput()} directory.
     * </p>
     *
     * @return a {@link Path} to the generated BOM file.
     */
    protected abstract Path doGenerate();

    protected abstract GeneratorType generatorType();

    protected String generatorArgs() {
        DefaultGeneratorConfig defaultGeneratorConfig = sbomerConfigProvider.getDefaultGenerationConfig()
                .forGenerator(generatorType());

        if (generator.getArgs() == null) {
            String defaultArgs = defaultGeneratorConfig.defaultArgs();
            log.debug("Using default arguments for the {} execution: {}", generatorType(), defaultArgs);

            return defaultArgs;
        } else {
            log.debug("Using provided arguments for the {} execution: {}", generatorType(), generator.getArgs());

            return generator.getArgs();
        }
    }

    protected String toolVersion() {
        DefaultGeneratorConfig defaultGeneratorConfig = sbomerConfigProvider.getDefaultGenerationConfig()
                .forGenerator(generatorType());

        if (generator.getVersion() == null) {
            String toolVersion = defaultGeneratorConfig.defaultVersion();
            log.debug("Using default tool version for the {} generator: {}", generatorType(), toolVersion);

            return toolVersion;
        } else {
            log.debug("Using provided version for the {} generator: {}", generatorType(), generator.getVersion());

            return generator.getVersion();
        }
    }

    @Override
    public Integer call() throws Exception {
        // Make sure there is no context
        MDCUtils.removeContext();
        // MDCUtils.addBuildContext(parent.getBuildId());

        // Fetch build information
        DeliverableAnalyzerOperation operation = pncService.getDeliverableAnalyzerOperation(parent.getOperationId());

        if (operation == null) {
            log.error("Could not fetch the PNC operation with id '{}'", parent.getOperationId());
            return CommandLine.ExitCode.SOFTWARE;
        }

        Path sbomPath = doGenerate();
        log.info("Generation finished, SBOM available at: '{}'", sbomPath.toAbsolutePath());
        return 0;
    }

}
