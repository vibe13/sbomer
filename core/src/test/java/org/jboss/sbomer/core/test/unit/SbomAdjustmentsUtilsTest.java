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
package org.jboss.sbomer.core.test.unit;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import org.apache.maven.model.Dependency;
import org.apache.maven.model.Model;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.jboss.sbomer.core.SchemaValidator;
import org.jboss.sbomer.core.errors.ApplicationException;
import org.jboss.sbomer.core.features.sbom.utils.SbomUtils;
import org.jboss.sbomer.core.features.sbom.utils.maven.MavenPomBuilder;
import org.junit.jupiter.api.Test;

import com.github.packageurl.PackageURL;

import lombok.extern.slf4j.Slf4j;

public class SbomAdjustmentsUtilsTest {

    static Path getPath(String fileName) {
        // return Paths.get("src", "test", "resources", "operation", fileName);
        return Paths.get("core", "src", "test", "resources", "operation", fileName);
    }

    public static void writePurlsToFile(List<String> purls, Path filePath) {
        Collections.sort(purls);
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath.toAbsolutePath().toString()))) {
            for (String str : purls) {
                writer.write(str);
                writer.newLine(); // Add newline after each string
            }
            System.out.println("Sorted strings written to file: " + filePath.toAbsolutePath());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        Path bomPath = getPath("bom.json");
        Path pomPath = getPath("pom.xml");

        System.out.println(
                "Adjusting SBOM: '" + bomPath.toAbsolutePath() + "' with POM: '" + pomPath.toAbsolutePath() + "'");
        Path destinationBom = Path.of(bomPath.toAbsolutePath().toString().replace("-bom.json", "-bom-enhanced.json"));

        Bom sbom = SbomUtils.fromPath(bomPath);
        if (sbom == null) {
            throw new ApplicationException("Cannot read the generated SBOM '{}'", bomPath.toAbsolutePath());
        }
        MavenPomBuilder mavenPomBuilder = MavenPomBuilder.build();
        Model model = mavenPomBuilder.readPomFile(pomPath);
        if (model == null) {
            throw new ApplicationException("Cannot read the created POM '{}'", pomPath.toAbsolutePath());
        }

        List<Dependency> dependencies = model.getDependencies();
        List<Component> components = sbom.getComponents();
        int depSize = dependencies != null ? dependencies.size() : 0;
        int compSize = components != null ? components.size() : 0;
        List<String> pomPurls = new ArrayList<String>();
        List<String> sbomPurls = new ArrayList<String>();

        for (int i = 0; i < depSize; i++) {
            Dependency pomDependency = dependencies.get(i);
            PackageURL purl = mavenPomBuilder.getPurlOf(pomDependency);
            pomPurls.add(purl.toString());
        }

        for (int i = 0; i < compSize; i++) {
            Component component = components.get(i);
            sbomPurls.add(component.getPurl().toString());
        }

        writePurlsToFile(pomPurls, Path.of(pomPath.toAbsolutePath().toString().replace("pom.xml", "pom-purls.txt")));
        writePurlsToFile(sbomPurls, Path.of(bomPath.toAbsolutePath().toString().replace("bom.json", "bom-purls.txt")));

        // if (depSize != compSize) {
        // System.out.println("The number of components inside the SBOM (" + compSize + ") is different from the number
        // of dependencies inside the POM ("+ depSize+ "), some adjustments need to be made!"
        // );
        // for (int i = 0; i < depSize; i++) {
        // Dependency pomDependency = dependencies.get(i);
        // PackageURL purl = mavenPomBuilder.getPurlOf(pomDependency);
        // if (purl == null) {
        // // Should never happen, but cannot do much about it, if it happens
        // continue;
        // }

        // Optional<Component> component = SbomUtils.findComponentWithPurl(purl.toString(), sbom);
        // if (component.isPresent()) {
        // // The dependency is present as a component in the BOM, cool, let's proceed
        // continue;
        // }

        // System.out.println(
        // "The dependency with PURL '{" + purl + "}' was not found in the generated SBOM, adding it manually!");
        // Optional<String> bestMatchingPurl = SbomUtils.findBestMatchingPurl(purl, sbom);
        // if (!bestMatchingPurl.isPresent()) {
        // System.out.println(
        // "Could not find a best matching PURL for the purl {" + purl + "}, this component cannot be added!");
        // continue;
        // }
        // Component bestMatchingComponent = SbomUtils.findComponentWithPurl(bestMatchingPurl.get(), sbom).get();
        // Component newComponent = SbomUtils.cloneWithPurl(bestMatchingComponent, purl);
        // System.out.println("Adding new cloned component: " + newComponent);
        // sbom.addComponent(newComponent);

        // org.cyclonedx.model.Dependency bomNewDependency = new org.cyclonedx.model.Dependency(purl.toString());
        // String mainComponentUrl = sbom.getMetadata().getComponent().getBomRef();
        // org.cyclonedx.model.Dependency bomMainDependency = null;
        // if (sbom.getDependencies() != null) {
        // for (org.cyclonedx.model.Dependency dependency : sbom.getDependencies()) {
        // if (mainComponentUrl.equals(dependency.getRef())) {
        // bomMainDependency = dependency;
        // break;
        // }
        // }
        // }
        // if (bomMainDependency == null) {
        // bomMainDependency = new org.cyclonedx.model.Dependency(mainComponentUrl);
        // }
        // bomMainDependency.addDependency(bomNewDependency);
        // sbom.addDependency(bomNewDependency);
        // }

        // // Write the new enhanced SBOM!
        // SbomUtils.toPath(sbom, destinationBom);
        // }
    }

}
