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

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Objects;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class MavenUtils {

    public static String minimizeMavenModel(Path xmlModelPath) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(xmlModelPath.toFile()))) {

            StringBuilder xmlContent = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                // Remove leading and trailing whitespace
                line = line.trim();
                // Append non-empty lines to the content
                if (!line.isEmpty()) {
                    xmlContent.append(line);
                }
            }
            return xmlContent.toString();
        }
    }

    // Method to calculate the similarity score between two PURLs; they must have same GA, classifier (if any) and type
    public static int calculateSimilarityOfPurls(PackageURL purl1, String purl) {
        PackageURL purl2;
        try {
            purl2 = new PackageURL(purl);
        } catch (MalformedPackageURLException e) {
            log.error("Error while parsing malformed purl: '{}'", purl);
            return -1;
        }

        String classifier1 = null;
        String classifier2 = null;
        String type1 = null;
        String type2 = null;
        if (purl1.getQualifiers() != null) {
            classifier1 = purl1.getQualifiers().get("classifier");
            type1 = purl1.getQualifiers().get("type");
        }
        if (purl2.getQualifiers() != null) {
            classifier2 = purl2.getQualifiers().get("classifier");
            type2 = purl2.getQualifiers().get("type");
        }
        if (!Objects.equals(purl1.getNamespace(), purl2.getNamespace())
                && !Objects.equals(purl1.getName(), purl2.getName()) && !Objects.equals(type1, type2)
                && !Objects.equals(classifier1, classifier2)) {
            return -1;
        }

        return calculateSimilarityOfVersions(purl1.getVersion(), purl2.getVersion());
    }

    // Method to calculate similarity score between two version strings
    public static int calculateSimilarityOfVersions(String version1, String version2) {
        // Split version strings into components
        String[] components1 = version1.split("\\.");
        String[] components2 = version2.split("\\.");

        // Compare major, minor, and micro components
        int majorScore = components1[0].equals(components2[0]) ? 3 : 0;
        int minorScore = components1.length > 1 && components2.length > 1 && components1[1].equals(components2[1]) ? 2
                : 0;
        int microScore = components1.length > 2 && components2.length > 2 && components1[2].equals(components2[2]) ? 1
                : 0;

        // Calculate overall similarity score
        return majorScore + minorScore + microScore;
    }

}
