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
package org.jboss.sbomer.core.features.sbom.utils.maven;

import org.apache.maven.model.Dependency;
import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.apache.maven.model.io.xpp3.MavenXpp3Writer;
import org.codehaus.plexus.util.WriterFactory;
import org.codehaus.plexus.util.xml.XmlStreamWriter;
import org.jboss.pnc.common.Strings;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;

@Getter
@Slf4j
@ToString
public class MavenPomBuilder {

    public static final String DEFAULT_MODEL_VERSION = "4.0.0";
    public static final String DEFAULT_DEPENDENCY_TYPE = "jar";

    Model model;

    public static MavenPomBuilder build() {
        return new MavenPomBuilder();
    }

    private MavenPomBuilder() {
        model = new Model();
    }

    public MavenPomBuilder createModel(String groupId, String artifactId, String version, String description) {
        return createModel(DEFAULT_MODEL_VERSION, groupId, artifactId, version, description);
    }

    public MavenPomBuilder createModel(
            String modelVersion,
            String groupId,
            String artifactId,
            String version,
            String description) {
        log.debug(
                "Creating new POM model with modelVersion: {}, groupId: {}, artifactId: {}, version:{}",
                modelVersion,
                groupId,
                artifactId,
                version);
        model = new Model();
        model.setModelVersion(modelVersion);
        model.setGroupId(groupId);
        model.setArtifactId(artifactId);
        model.setVersion(version);
        model.setDescription(description);
        return this;
    }

    public MavenPomBuilder addDependency(String groupId, String artifactId, String version, String pncArtifactId) {
        return addDependency(groupId, artifactId, version, DEFAULT_DEPENDENCY_TYPE, null, pncArtifactId);
    }

    public MavenPomBuilder addDependency(
            String groupId,
            String artifactId,
            String version,
            String classifier,
            String pncArtifactId) {
        return addDependency(groupId, artifactId, version, DEFAULT_DEPENDENCY_TYPE, classifier, pncArtifactId);

    }

    public MavenPomBuilder addDependency(
            String groupId,
            String artifactId,
            String version,
            String type,
            String classifier,
            String pncArtifactId) {

        Dependency dependency = new Dependency();
        dependency.setGroupId(groupId);
        dependency.setArtifactId(artifactId);
        dependency.setVersion(version);
        if (!Strings.isEmpty(type)) {
            dependency.setType(type);
        }
        if (!Strings.isEmpty(classifier)) {
            dependency.setClassifier(classifier);
        }

        log.debug("Adding {}, with classifier: {}, pncArtifactId: {}", dependency, classifier, pncArtifactId);
        model.addDependency(dependency);

        String propertyKey = dependency.getGroupId() + "." + dependency.getArtifactId() + "." + dependency.getVersion();
        log.debug("Adding property with key: '{}', value: '{}'", propertyKey, pncArtifactId);
        model.addProperty(propertyKey, pncArtifactId);

        return this;
    }

    public void writePomFile(Path filePath) throws IOException {

        // Create the directory if it doesn't exist
        Path directoryPath = filePath.getParent();
        if (!Files.exists(directoryPath)) {
            Files.createDirectories(directoryPath);
        }

        // Create the file
        Files.createFile(filePath);

        try (XmlStreamWriter fileWriter = WriterFactory.newXmlWriter(filePath.toFile())) {
            MavenXpp3Writer writer = new MavenXpp3Writer();
            writer.write(fileWriter, model);
            log.debug("POM file created successfully: {}", filePath.toAbsolutePath());
        } catch (IOException e) {
            log.error("Error while writing the POM model to file", e);
            throw e;
        }
    }

    public Model readPomFile(Path pomPath) {

        try (FileInputStream fis = new FileInputStream(pomPath.toFile())) {

            MavenXpp3Reader reader = new MavenXpp3Reader();
            return reader.read(fis);

        } catch (FileNotFoundException e) {
            log.error("The POM file specified '{}' does no exist", pomPath.toAbsolutePath(), e);
            return null;
        } catch (IOException e) {
            log.error("An error was encountered while reading the POM file '{}'", pomPath.toAbsolutePath(), e);
            return null;
        } catch (Exception e) {
            log.error("An error was encountered while parsing the POM file '{}'", pomPath.toAbsolutePath(), e);
            return null;
        }
    }

    public PackageURL getPurlOf(Dependency dependency) {

        String type = dependency.getType() == null ? DEFAULT_DEPENDENCY_TYPE : dependency.getType();
        PackageURLBuilder packageURLBuilder = PackageURLBuilder.aPackageURL()
                .withNamespace(dependency.getGroupId())
                .withName(dependency.getArtifactId())
                .withVersion(dependency.getVersion())
                .withType("maven")
                .withQualifier("type", type);
        if (dependency.getClassifier() != null) {
            packageURLBuilder.withQualifier("classifier", dependency.getClassifier());
        }
        try {
            return packageURLBuilder.build();
        } catch (MalformedPackageURLException e) {
            log.error(
                    "There was an error building the PURL with namespace:{}, name: {}, version:{}, type: {}, classifier: {}",
                    dependency.getGroupId(),
                    dependency.getArtifactId(),
                    dependency.getVersion(),
                    type,
                    dependency.getClassifier(),
                    e);
            return null;
        }
    }

}
