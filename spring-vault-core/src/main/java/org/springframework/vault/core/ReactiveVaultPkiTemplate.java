/*
 * Copyright 2016-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.vault.core;

import org.springframework.util.Assert;
import org.springframework.vault.VaultException;
import org.springframework.vault.client.VaultResponses;
import org.springframework.vault.core.VaultPkiOperations.Encoding;
import org.springframework.vault.support.VaultCertificateRequest;
import org.springframework.vault.support.VaultCertificateResponse;
import org.springframework.vault.support.VaultIssuerCertificateRequestResponse;
import org.springframework.vault.support.VaultSignCertificateRequestResponse;
import org.springframework.web.client.HttpStatusCodeException;
import reactor.core.publisher.Mono;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Collections;
import java.util.Locale;
import java.util.Map;

import static org.springframework.vault.core.VaultPkiTemplate.createIssueRequest;

/**
 * Default implementation of {@link VaultPkiOperations}.
 *
 * @author Mei Chen
 */
public class ReactiveVaultPkiTemplate implements ReactiveVaultPkiOperations {

    private final ReactiveVaultOperations reactiveVaultOperations;

    private final String path;

    /**
     * Create a new {@link VaultPkiTemplate} given {@link VaultOperations} and the mount
     * {@code path}.
     *
     * @param reactiveVaultOperations must not be {@literal null}.
     * @param path                    must not be empty or {@literal null}.
     */
    public ReactiveVaultPkiTemplate(ReactiveVaultOperations reactiveVaultOperations, String path) {

        Assert.notNull(reactiveVaultOperations, "VaultOperations must not be null");
        Assert.hasText(path, "Path must not be empty");

        this.reactiveVaultOperations = reactiveVaultOperations;
        this.path = path;
    }

    @Override
    public Mono<VaultCertificateResponse> issueCertificate(String roleName, VaultCertificateRequest certificateRequest)
            throws VaultException {

        Assert.hasText(roleName, "Role name must not be empty");
        Assert.notNull(certificateRequest, "Certificate request must not be null");

        return requestCertificate(roleName, "{path}/issue/{roleName}", createIssueRequest(certificateRequest),
                VaultCertificateResponse.class);
    }

    @Override
    public Mono<VaultSignCertificateRequestResponse> signCertificateRequest(
            String roleName, String csr, VaultCertificateRequest certificateRequest) throws VaultException {

        Assert.hasText(roleName, "Role name must not be empty");
        Assert.hasText(csr, "CSR name must not be empty");
        Assert.notNull(certificateRequest, "Certificate request must not be null");

        Map<String, Object> body = createIssueRequest(certificateRequest);
        body.put("csr", csr);

        return requestCertificate(roleName, "{path}/sign/{roleName}", body, VaultSignCertificateRequestResponse.class);
    }

    private <T> Mono<T> requestCertificate(String roleName, String requestPath, Map<String, Object> request,
                                           Class<T> responseType) {

        request.putIfAbsent("format", "der");

        return this.reactiveVaultOperations.doWithSession(webClient -> {

            return webClient.post()
                .uri(uriBuilder -> uriBuilder.path(requestPath).build(this.path, roleName))
                .bodyValue(request)
                .retrieve()
                .bodyToMono(responseType)
                .doOnNext(response -> {
                    Assert.state(response != null, "VaultCertificateResponse must not be null");
                })
                .onErrorResume(HttpStatusCodeException.class, e -> Mono.error(VaultResponses.buildException(e)));
        });
    }

    @Override
    public Mono<Void> revoke(String serialNumber) throws VaultException {

        Assert.hasText(serialNumber, "Serial number must not be null or empty");

        return this.reactiveVaultOperations.doWithSession(webClient -> {

            return webClient.post()
                .uri(uriBuilder -> uriBuilder.path("{path}/revoke").build(this.path))
                .bodyValue(Collections.singletonMap("serial_number", serialNumber))
                .retrieve()
                .bodyToMono(Map.class)
                .onErrorResume(HttpStatusCodeException.class, e -> Mono.error(VaultResponses.buildException(e)))
                .then();
        });
    }

    @Override
    public Mono<InputStream> getCrl(Encoding encoding) throws VaultException {

        Assert.notNull(encoding, "Encoding must not be null");

        return this.reactiveVaultOperations.doWithSession(webClient -> {

            String requestPath = encoding == Encoding.DER ? "{path}/crl" : "{path}/crl/pem";
            return webClient.get()
                .uri(uriBuilder -> uriBuilder.path(requestPath).build(this.path))
                .retrieve()
                .toEntity(byte[].class)
                .filter(response -> response.getStatusCode().is2xxSuccessful() && response.hasBody())
                .map(response -> new ByteArrayInputStream(response.getBody()))
                .cast(InputStream.class)
                .onErrorResume(HttpStatusCodeException.class, e -> Mono.error(VaultResponses.buildException(e)));
        });
    }

    @Override
    public Mono<VaultIssuerCertificateRequestResponse> getIssuerCertificate(String issuer) throws VaultException {

        Assert.hasText(issuer, "Issuer must not be empty");

        return this.reactiveVaultOperations.doWithSession(webClient -> {

            return webClient.get()
                .uri(uriBuilder -> uriBuilder.path("{path}/issuer/{issuer}").build(this.path, issuer))
                .retrieve()
                .bodyToMono(VaultIssuerCertificateRequestResponse.class)
                .onErrorResume(HttpStatusCodeException.class, e -> Mono.error(VaultResponses.buildException(e)));
        });
    }

    @Override
    public Mono<InputStream> getIssuerCertificate(String issuer, Encoding encoding) throws VaultException {

        Assert.hasText(issuer, "Issuer must not be empty");
        Assert.notNull(encoding, "Encoding must not be null");

        return this.reactiveVaultOperations.doWithSession(webClient -> {

            String requestPath = "{path}/issuer/{issuer}/%s".formatted(encoding.name().toLowerCase(Locale.ROOT));
            return webClient.get()
                .uri(uriBuilder -> uriBuilder.path(requestPath).build(this.path, issuer))
                .retrieve()
                .toEntity(byte[].class)
                .filter(response -> response.getStatusCode().is2xxSuccessful() && response.hasBody())
                .map(response -> new ByteArrayInputStream(response.getBody()))
                .cast(InputStream.class)
                .onErrorResume(HttpStatusCodeException.class, e -> Mono.error(VaultResponses.buildException(e)));
        });
    }
}
