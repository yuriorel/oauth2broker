package com.oauth2broker.store;

import java.io.IOException;
import java.util.stream.Gatherers;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import com.oauth2broker.client.ClientRepository;
import com.oauth2broker.user.UserRepository;

import tools.jackson.databind.json.JsonMapper;

/** Writes the clients and users from {@code seed.json} to Redis at startup. Rerunning overwrites them with the same data. */
@Component
public class SeedLoader implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(SeedLoader.class);
    private static final int MAX_CONCURRENT_WRITES = 8;

    private final Resource seedFile;
    private final JsonMapper json;
    private final ClientRepository clients;
    private final UserRepository users;

    public SeedLoader(@Value("classpath:seed.json") Resource seedFile, JsonMapper json, ClientRepository clients,
                      UserRepository users) {
        this.seedFile = seedFile;
        this.json = json;
        this.clients = clients;
        this.users = users;
    }

    @Override
    public void run(ApplicationArguments args) throws IOException {
        Seed seed;
        try (var in = seedFile.getInputStream()) {
            seed = json.readValue(in, Seed.class);
        }
        // mapConcurrent runs each write on its own virtual thread.
        var written = Stream.concat(
                        seed.clients().stream().map(client -> (Runnable) () -> clients.save(client)),
                        seed.users().stream().map(user -> (Runnable) () -> users.save(user)))
                .gather(Gatherers.mapConcurrent(MAX_CONCURRENT_WRITES, write -> {
                    write.run();
                    return write;
                }))
                .toList();
        log.info("Seeded {} entries ({} clients, {} users)", written.size(), seed.clients().size(), seed.users().size());
    }
}
