package kz.ncanode.exception;

import lombok.extern.slf4j.Slf4j;

/**
 * Единая обёртка для «серверных» операций: пробрасывает {@link ApplicationException}
 * (клиентские / доменные ошибки) как есть, а любую другую проверяемую ошибку логирует
 * и оборачивает в {@link ServerException} с понятным контекстом.
 *
 * <p>Заменяет дублирующийся по всем сервисам блок
 * {@code catch (ClientException e) { throw e; } catch (Exception e) { throw new ServerException(...); }}.
 */
@Slf4j
public final class ServerOp {
    private ServerOp() {
    }

    @FunctionalInterface
    public interface Call<T> {
        T get() throws Exception;
    }

    @FunctionalInterface
    public interface Run {
        void run() throws Exception;
    }

    public static <T> T call(String context, Call<T> body) {
        try {
            return body.get();
        } catch (ApplicationException e) {
            throw e;
        } catch (KeyException e) {
            // ошибка чтения PKCS12-ключа — вина клиента (неверный пароль / битый контейнер)
            throw new ClientException(e.getMessage(), e);
        } catch (Exception e) {
            String message = (context == null || context.isBlank())
                ? e.getMessage()
                : context + ": " + e.getMessage();
            log.error(message, e);
            throw new ServerException(message, e);
        }
    }

    public static void run(String context, Run body) {
        call(context, () -> {
            body.run();
            return null;
        });
    }

    /**
     * Как {@link #call}, но невыясненную ошибку трактует как вину клиента (для {@code verify}/{@code decode}
     * эндпоинтов, где обычная причина — присланный на проверку мусор).
     */
    public static <T> T callClient(String context, Call<T> body) {
        try {
            return body.get();
        } catch (ApplicationException e) {
            throw e;
        } catch (Exception e) {
            String message = (context == null || context.isBlank())
                ? e.getMessage()
                : context + ": " + e.getMessage();
            throw new ClientException(message, e);
        }
    }
}
