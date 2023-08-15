package com.auth0.jwt;


import com.auth0.jwt.algorithms.Algorithm;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.infra.Blackhole;

public class JWTCreatorBenchmark {

    private static final String claimsJson = "{\"stringClaim\": \"someClaim\", \"intClaim\": 1, \"nestedClaim\": { \"listClaim\": [ \"1\", \"2\" ]}}";
    private static final String secret = "secret";

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public void throughputCreateTime(Blackhole blackhole) {
        blackhole.consume(JWTCreator.init()
                .withHeader(claimsJson)
                .sign(Algorithm.HMAC256(secret)));
    }
}
