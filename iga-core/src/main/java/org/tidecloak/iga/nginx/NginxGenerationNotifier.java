package org.tidecloak.iga.nginx;

import org.infinispan.protostream.FileDescriptorSource;
import org.infinispan.protostream.MessageMarshaller;
import org.infinispan.protostream.SerializationContext;
import org.infinispan.protostream.SerializationContextInitializer;
import org.jboss.logging.Logger;
import org.keycloak.cluster.ClusterEvent;
import org.keycloak.cluster.ClusterProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakTransaction;

import java.io.IOException;

/**
 * Tells the other replicas that a new nginx generation exists.
 *
 * <p>The event carries the generation for logging only. The database stays authoritative — a
 * receiver re-reads the counter and the certificate state rather than trusting the payload — so
 * nothing secret ever goes over the wire.
 */
public final class NginxGenerationNotifier {

    public static final String TASK_KEY = "tidecloak-private-tls-generation";

    private static final Logger log = Logger.getLogger(NginxGenerationNotifier.class);

    private NginxGenerationNotifier() {
    }

    /**
     * Notify the cluster once the current transaction commits.
     *
     * <p>After commit, not during: a replica that reacted to the event while the writer was still
     * uncommitted would read the old state, record the new generation as applied, and never look
     * again. Enlisting after completion also means a rollback sends nothing.
     *
     * <p>Failure to notify is logged, not thrown. Notification only makes convergence fast —
     * periodic reconciliation is what makes it correct — so a dead transport must not fail an
     * issuance that has already committed.
     */
    public static void notifyAfterCommit(KeycloakSession session, long generation) {
        session.getTransactionManager().enlistAfterCompletion(new AfterCommit() {
            @Override
            public void commit() {
                try {
                    session.getProvider(ClusterProvider.class)
                            .notify(TASK_KEY, new GenerationEvent(generation), false);
                } catch (Exception e) {
                    log.warnf(e, "Could not notify the cluster of nginx generation %d; replicas will "
                            + "pick it up on their next periodic reconcile.", generation);
                }
            }
        });
    }

    /** Payload is advisory; receivers re-read the counter from the database. */
    public static final class GenerationEvent implements ClusterEvent {

        static final String TYPE_NAME = "tidecloak.nginx.ProxyTlsGenerationEvent";

        private final long generation;

        public GenerationEvent(long generation) {
            this.generation = generation;
        }

        public long getGeneration() {
            return generation;
        }
    }

    /**
     * Marshaller for {@link GenerationEvent}, hand-written rather than generated so the module needs
     * no annotation processor. Registered via
     * {@code META-INF/services/org.infinispan.protostream.SerializationContextInitializer}; without
     * it Infinispan cannot serialise the event and only same-node delivery works.
     */
    public static final class Schema implements SerializationContextInitializer {

        @Override
        public String getProtoFileName() {
            return "tidecloak-nginx.proto";
        }

        @Override
        public String getProtoFile() {
            return "syntax = \"proto2\";\n"
                    + "package tidecloak.nginx;\n"
                    + "message ProxyTlsGenerationEvent {\n"
                    + "  optional int64 generation = 1;\n"
                    + "}\n";
        }

        @Override
        public void registerSchema(SerializationContext context) {
            context.registerProtoFiles(FileDescriptorSource.fromString(getProtoFileName(), getProtoFile()));
        }

        @Override
        public void registerMarshallers(SerializationContext context) {
            context.registerMarshaller(new MessageMarshaller<GenerationEvent>() {
                @Override
                public Class<GenerationEvent> getJavaClass() {
                    return GenerationEvent.class;
                }

                @Override
                public String getTypeName() {
                    return GenerationEvent.TYPE_NAME;
                }

                @Override
                public GenerationEvent readFrom(ProtoStreamReader reader) throws IOException {
                    Long generation = reader.readLong("generation");
                    return new GenerationEvent(generation == null ? 0L : generation);
                }

                @Override
                public void writeTo(ProtoStreamWriter writer, GenerationEvent event) throws IOException {
                    writer.writeLong("generation", event.generation);
                }
            });
        }
    }

    /** Only {@code commit()} matters; the rest of KeycloakTransaction is inert for an after-hook. */
    private abstract static class AfterCommit implements KeycloakTransaction {

        @Override
        public void begin() {
        }

        @Override
        public void rollback() {
        }

        @Override
        public void setRollbackOnly() {
        }

        @Override
        public boolean getRollbackOnly() {
            return false;
        }

        @Override
        public boolean isActive() {
            return true;
        }
    }
}
