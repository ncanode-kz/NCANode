package kz.ncanode.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Помечает код, недостижимый для тестов (например, вызовы {@link System#exit}
 * при фатальной ошибке конфигурации). JaCoCo исключает из отчёта любой элемент,
 * помеченный аннотацией с именем {@code Generated}.
 */
@Retention(RetentionPolicy.CLASS)
@Target({ElementType.METHOD, ElementType.TYPE, ElementType.CONSTRUCTOR})
public @interface Generated {
}
