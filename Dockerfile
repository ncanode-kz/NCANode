FROM amazoncorretto:17-alpine AS builder

WORKDIR /app
COPY build/libs/NCANode.jar app.jar

RUN $JAVA_HOME/bin/jlink \
    --module-path $JAVA_HOME/jmods \
    --add-modules java.base,java.logging,java.sql \
    --strip-debug \
    --compress=2 \
    --no-header-files \
    --no-man-pages \
    --output /javaruntime

FROM alpine:3.19

RUN apk add --no-cache bash wget

WORKDIR /app
COPY --from=builder /javaruntime /opt/jre
COPY --from=builder /app/app.jar /app/NCANode.jar

ENV PATH="/opt/jre/bin:$PATH"
ENV JAVA_OPTS="-Xms128m -Xmx512m"

EXPOSE 14579

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar NCANode.jar"]

HEALTHCHECK --interval=20s --timeout=30s --retries=7 \
    CMD wget -O - http://127.0.0.1:14579/actuator/health å| grep -v DOWN || exit 1
