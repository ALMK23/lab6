package ru.mtuci.translations;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;

import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Интеграционные тесты на настоящем PostgreSQL (Testcontainers, нужен запущенный Docker;
 * без Docker тесты пропускаются). В контейнере выполняется тот же db/init.sql, что и в проде,
 * поэтому приложение работает от пользователя с ограниченными правами.
 * Администратор admin@demo.local создаётся миграцией V3.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers(disabledWithoutDocker = true)
class ApiIntegrationTest {

    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16")
            .withCopyFileToContainer(MountableFile.forHostPath("db/init.sql"), "/db/init.sql");

    private static final AtomicInteger SEQ = new AtomicInteger();
    private static final String PASSWORD = "Str0ng#Pass";
    private static final Account ADMIN = new Account(0, "admin@demo.local", "Admin#2024");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) throws Exception {
        if (!POSTGRES.isRunning()) {
            POSTGRES.start();
            var result = POSTGRES.execInContainer("psql", "-U", POSTGRES.getUsername(), "-d", "postgres",
                    "-v", "ON_ERROR_STOP=1", "-v", "owner_password=owner_pw", "-v", "app_password=app_pw",
                    "-f", "/db/init.sql");
            if (result.getExitCode() != 0) {
                throw new IllegalStateException("init.sql failed: " + result.getStderr());
            }
        }
        String key = java.util.Base64.getEncoder().encodeToString(io.jsonwebtoken.Jwts.SIG.HS256.key().build().getEncoded());
        registry.add("JWT_SECRET", () -> key);
        registry.add("DB_HOST", POSTGRES::getHost);
        registry.add("DB_PORT", () -> POSTGRES.getMappedPort(5432));
        registry.add("DB_NAME", () -> "translations");
        registry.add("DB_SCHEMA", () -> "app");
        registry.add("DB_OWNER_USER", () -> "translations_owner");
        registry.add("DB_OWNER_PASSWORD", () -> "owner_pw");
        registry.add("DB_APP_USER", () -> "translations_app");
        registry.add("DB_APP_PASSWORD", () -> "app_pw");
    }

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper mapper;

    record Account(long id, String email, String password) {
    }

    // ------------------------------------------------------- аутентификация

    @Test
    void requestsWithoutLoginAreUnauthorized() throws Exception {
        mvc.perform(get("/api/translation-projects")).andExpect(status().isUnauthorized());

        // неверный пароль и несуществующий пользователь — одинаковый ответ
        String wrongPassword = mvc.perform(get("/api/translation-projects").with(httpBasic(ADMIN.email(), "Wrong#123")))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();
        String noSuchUser = mvc.perform(get("/api/translation-projects").with(httpBasic("nobody@test.local", "Wrong#123")))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();
        String m1 = mapper.readTree(wrongPassword).get("message").asText();
        String m2 = mapper.readTree(noSuchUser).get("message").asText();
        assertEquals(m1, m2);

        send(ADMIN, "GET", "/api/auth/me", null, 200).andExpect(jsonPath("$.role").value("ADMIN"));
    }

    @Test
    @DirtiesContext(methodMode = DirtiesContext.MethodMode.BEFORE_METHOD)
    void csrfTokenIsRequiredForChanges() throws Exception {
        // без токена — 403
        mvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson("Без токена", "nocsrf" + SEQ.incrementAndGet() + "@test.local", PASSWORD)))
                .andExpect(status().isForbidden());

        // Получаем токен и соответствующую cookie.
        MvcResult csrfResult = mvc.perform(get("/api/auth/csrf"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.headerName").isNotEmpty())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andReturn();
        var cookie = csrfResult.getResponse().getCookie("XSRF-TOKEN");
        assertNotNull(cookie);
        JsonNode csrfBody = mapper.readTree(csrfResult.getResponse().getContentAsString());
        String headerName = csrfBody.get("headerName").asText();
        String token = csrfBody.get("token").asText();

        mvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .cookie(cookie).header(headerName, token)
                        .content(registerJson("С токеном", "csrf" + SEQ.incrementAndGet() + "@test.local", PASSWORD)))
                .andExpect(status().isCreated());

        // поддельный токен — 403
        mvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .cookie(cookie).header(headerName, "fake")
                        .content(registerJson("Подделка", "fake" + SEQ.incrementAndGet() + "@test.local", PASSWORD)))
                .andExpect(status().isForbidden());
    }

    @Test
    void registrationGivesOnlyTranslatorRole() throws Exception {
        String email = "hacker" + SEQ.incrementAndGet() + "@test.local";
        mvc.perform(post("/api/auth/register").with(csrf()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"Хакер\",\"email\":\"" + email + "\",\"password\":\"" + PASSWORD
                                + "\",\"role\":\"ADMIN\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.role").value("TRANSLATOR"))
                .andExpect(jsonPath("$.passwordHash").doesNotExist());

        Account hacker = new Account(0, email, PASSWORD);
        send(hacker, "GET", "/api/users", null, 403);
        send(hacker, "POST", "/api/translation-projects", "{\"name\":\"X\",\"targetLanguage\":\"en\"}", 403);
    }

    @Test
    void registrationChecksPasswordAndEmail() throws Exception {
        register("Слабый", "weak" + SEQ.incrementAndGet() + "@test.local", "12345678", 400);
        register("Короткий", "short" + SEQ.incrementAndGet() + "@test.local", "Ab#1", 400);
        String email = "same" + SEQ.incrementAndGet() + "@test.local";
        register("А", email, PASSWORD, 201);
        register("Б", email.toUpperCase(), PASSWORD, 409);
    }

    @Test
    void accountIsLockedAfterFiveWrongPasswords() throws Exception {
        Account user = translator("Жертва подбора");
        for (int i = 0; i < 5; i++) {
            mvc.perform(get("/api/auth/me").with(httpBasic(user.email(), "Wrong#" + i)))
                    .andExpect(status().isUnauthorized());
        }
        // даже верный пароль не подходит, пока действует блокировка
        mvc.perform(get("/api/auth/me").with(httpBasic(user.email(), user.password())))
                .andExpect(status().isUnauthorized());

        send(ADMIN, "POST", "/api/users/" + user.id() + "/unblock", null, 200);
        send(user, "GET", "/api/auth/me", null, 200);
    }

    @Test
    void blockedUserCannotLogin() throws Exception {
        Account user = translator("Нарушитель");
        send(ADMIN, "POST", "/api/users/" + user.id() + "/block", null, 200)
                .andExpect(jsonPath("$.status").value("BLOCKED"));
        mvc.perform(get("/api/auth/me").with(httpBasic(user.email(), user.password())))
                .andExpect(status().isUnauthorized());
        send(ADMIN, "POST", "/api/users/" + user.id() + "/unblock", null, 200);
        send(user, "GET", "/api/auth/me", null, 200);
    }

    // ------------------------------------------------------- авторизация

    @Test
    void usersAreManagedOnlyByAdmin() throws Exception {
        Account translator = translator("Переводчик");
        Account other = translator("Другой");
        send(translator, "GET", "/api/users", null, 403);
        send(translator, "GET", "/api/users/" + translator.id(), null, 200);
        send(translator, "GET", "/api/users/" + other.id(), null, 403);
        send(translator, "PATCH", "/api/users/" + other.id(), "{\"name\":\"Взлом\"}", 403);
        send(translator, "PATCH", "/api/users/" + translator.id() + "/role", "{\"role\":\"ADMIN\"}", 403);
        send(translator, "DELETE", "/api/users/" + other.id(), null, 403);

        send(ADMIN, "GET", "/api/users", null, 200);
        send(ADMIN, "PATCH", "/api/users/" + translator.id() + "/role", "{\"role\":\"EDITOR\"}", 200)
                .andExpect(jsonPath("$.role").value("EDITOR"));
        // админ не может заблокировать / удалить сам себя
        long adminId = id(send(ADMIN, "GET", "/api/auth/me", null, 200));
        send(ADMIN, "POST", "/api/users/" + adminId + "/block", null, 409);
        send(ADMIN, "DELETE", "/api/users/" + adminId, null, 409);
    }

    @Test
    void editorWithProjectsCannotBeDemoted() throws Exception {
        Account editor = editor("Редактор");
        project(editor);
        send(ADMIN, "PATCH", "/api/users/" + editor.id() + "/role", "{\"role\":\"TRANSLATOR\"}", 409);
    }

    @Test
    void editorChangesOnlyOwnProjects() throws Exception {
        Account owner = editor("Владелец");
        Account stranger = editor("Чужой редактор");
        long project = project(owner);
        send(stranger, "PATCH", "/api/translation-projects/" + project, "{\"name\":\"Чужое\"}", 403);
        send(stranger, "POST", "/api/source-segments", "{\"projectId\":" + project + ",\"sourceText\":\"X\"}", 403);
        send(stranger, "POST", "/api/translation-projects/" + project + "/start", null, 403);
        send(stranger, "DELETE", "/api/translation-projects/" + project, null, 403);
        // администратор может удалить любой проект
        send(ADMIN, "DELETE", "/api/translation-projects/" + project, null, 204);
    }

    // ------------------------------------------------------------------ CRUD

    @Test
    void crudAndCascadeDelete() throws Exception {
        Account owner = editor("Владелец");
        long project = id(send(owner, "POST", "/api/translation-projects",
                "{\"name\":\"Сайт\",\"targetLanguage\":\"en\"}", 201)
                .andExpect(jsonPath("$.status").value("DRAFT"))
                .andExpect(jsonPath("$.ownerId").value(owner.id())));
        long segment = segment(owner, project, "Привет");
        send(owner, "POST", "/api/source-segments", "{\"projectId\":" + project + ",\"sourceText\":\"Дубль\",\"position\":1}", 409);

        send(owner, "PATCH", "/api/translation-projects/" + project, "{\"name\":\"Сайт v2\"}", 200)
                .andExpect(jsonPath("$.name").value("Сайт v2"));
        send(owner, "PATCH", "/api/translation-projects/" + project, "{\"status\":\"COMPLETED\"}", 400);

        start(owner, project);
        Account translator = translator("Переводчик");
        long translation = translation(translator, segment, "Hello");
        send(translator, "POST", "/api/translations/" + translation + "/submit", null, 200);
        long comment = id(send(owner, "POST", "/api/editorial-comments",
                "{\"translationId\":" + translation + ",\"text\":\"Проверьте пунктуацию\"}", 201));

        send(owner, "DELETE", "/api/translation-projects/" + project, null, 204);
        send(owner, "GET", "/api/source-segments/" + segment, null, 404);
        send(owner, "GET", "/api/translations/" + translation, null, 404);
        send(owner, "GET", "/api/editorial-comments/" + comment, null, 404);
    }

    @Test
    void referencesToMissingObjectsAreBadRequest() throws Exception {
        Account editor = editor("Редактор");
        send(editor, "POST", "/api/source-segments", "{\"projectId\":999999,\"sourceText\":\"X\"}", 400);
        send(editor, "GET", "/api/translations/999999", null, 404);
    }

    // ------------------------------------------------------- бизнес-операции

    @Test
    void fullReviewWorkflow() throws Exception {
        Account editor = editor("Редактор");
        Account translator = translator("Переводчик");
        long project = project(editor);
        long seg1 = segment(editor, project, "Добро пожаловать");
        long seg2 = segment(editor, project, "До свидания");

        // переводы до запуска проекта создавать нельзя
        send(translator, "POST", "/api/translations", "{\"segmentId\":" + seg1 + ",\"text\":\"Welcome\"}", 409);
        send(translator, "POST", "/api/translation-projects/" + project + "/start", null, 403);
        start(editor, project);

        long t1 = translation(translator, seg1, "Welcome");
        long t2 = translation(translator, seg2, "Goodbye");

        send(editor, "POST", "/api/translations/" + t1 + "/submit", null, 403);       // не автор
        send(editor, "PATCH", "/api/translations/" + t1, "{\"text\":\"Чужая правка\"}", 403);
        send(translator, "POST", "/api/translations/" + t1 + "/submit", null, 200)
                .andExpect(jsonPath("$.status").value("SUBMITTED"));

        // отклонение: перевод и замечание меняются вместе
        send(translator, "POST", "/api/translations/" + t1 + "/reject", "{\"comment\":\"Сам себе\"}", 403);
        String rejected = send(editor, "POST", "/api/translations/" + t1 + "/reject",
                "{\"comment\":\"Добавьте восклицательный знак\"}", 200)
                .andExpect(jsonPath("$.translation.status").value("REJECTED"))
                .andExpect(jsonPath("$.comment.status").value("OPEN"))
                .andReturn().getResponse().getContentAsString();
        long c1 = mapper.readTree(rejected).at("/comment/id").asLong();

        send(translator, "POST", "/api/translations/" + t1 + "/submit", null, 409);   // открытое замечание
        send(editor, "POST", "/api/editorial-comments/" + c1 + "/resolve", null, 403);
        send(translator, "POST", "/api/editorial-comments/" + c1 + "/resolve",
                "{\"translationText\":\"Welcome!\"}", 200)
                .andExpect(jsonPath("$.comment.status").value("RESOLVED"))
                .andExpect(jsonPath("$.translation.text").value("Welcome!"));
        send(translator, "POST", "/api/translations/" + t1 + "/submit", null, 200);

        send(translator, "POST", "/api/translations/" + t1 + "/approve", null, 403);
        send(editor, "POST", "/api/translations/" + t1 + "/approve", null, 200)
                .andExpect(jsonPath("$.project.status").value("IN_PROGRESS"));
        send(editor, "POST", "/api/translation-projects/" + project + "/complete", null, 409);

        send(translator, "POST", "/api/translations/" + t2 + "/submit", null, 200);
        long c2 = id(send(editor, "POST", "/api/editorial-comments",
                "{\"translationId\":" + t2 + ",\"text\":\"Вопрос\"}", 201));
        send(editor, "POST", "/api/translations/" + t2 + "/approve", null, 409);
        send(translator, "POST", "/api/editorial-comments/" + c2 + "/dismiss", null, 403);
        send(editor, "POST", "/api/editorial-comments/" + c2 + "/dismiss", null, 200)
                .andExpect(jsonPath("$.status").value("REJECTED"));
        send(editor, "POST", "/api/translations/" + t2 + "/approve", null, 200)
                .andExpect(jsonPath("$.translation.status").value("APPROVED"))
                .andExpect(jsonPath("$.project.status").value("REVIEW"));

        send(editor, "POST", "/api/source-segments", "{\"projectId\":" + project + ",\"sourceText\":\"Поздно\"}", 409);
        send(editor, "POST", "/api/translation-projects/" + project + "/complete", null, 200)
                .andExpect(jsonPath("$.status").value("COMPLETED"));
        send(ADMIN, "DELETE", "/api/users/" + translator.id(), null, 409);
        send(editor, "POST", "/api/translation-projects/" + project + "/archive", null, 200)
                .andExpect(jsonPath("$.status").value("ARCHIVED"));
        send(editor, "PATCH", "/api/translation-projects/" + project, "{\"name\":\"Новое\"}", 409);
    }

    @Test
    void onlyOneActiveTranslationPerSegment() throws Exception {
        Account editor = editor("Редактор");
        Account a = translator("Автор А");
        Account b = translator("Автор Б");
        long project = project(editor);
        long seg = segment(editor, project, "Текст");
        start(editor, project);
        long ta = translation(a, seg, "Text A");
        long tb = translation(b, seg, "Text B");
        send(a, "POST", "/api/translations/" + ta + "/submit", null, 200);
        send(b, "POST", "/api/translations/" + tb + "/submit", null, 409);
    }

    @Test
    void editorCannotApproveOwnTranslation() throws Exception {
        Account editor = editor("Редактор");
        long project = project(editor);
        long seg = segment(editor, project, "Текст");
        start(editor, project);
        long t = translation(editor, seg, "Text");
        send(editor, "POST", "/api/translations/" + t + "/submit", null, 200);
        send(editor, "POST", "/api/translations/" + t + "/approve", null, 403);
    }

    @Test
    void startRequiresSegments() throws Exception {
        Account editor = editor("Редактор");
        long project = project(editor);
        send(editor, "POST", "/api/translation-projects/" + project + "/start", null, 409);
    }

    // ------------------------------------------------------------- помощники

    /** Запрос от имени пользователя: HTTP Basic + CSRF-токен. */
    private ResultActions send(Account as, String method, String url, String json, int expected) throws Exception {
        MockHttpServletRequestBuilder builder = switch (method) {
            case "GET" -> get(url);
            case "POST" -> post(url);
            case "PATCH" -> patch(url);
            case "DELETE" -> delete(url);
            default -> throw new IllegalArgumentException(method);
        };
        builder.with(httpBasic(as.email(), as.password())).with(csrf());
        if (json != null) {
            builder.contentType(MediaType.APPLICATION_JSON).content(json);
        }
        return mvc.perform(builder).andExpect(status().is(expected));
    }

    private long id(ResultActions actions) throws Exception {
        JsonNode node = mapper.readTree(actions.andReturn().getResponse().getContentAsString());
        return node.get("id").asLong();
    }

    private String registerJson(String name, String email, String password) {
        return "{\"name\":\"" + name + "\",\"email\":\"" + email + "\",\"password\":\"" + password + "\"}";
    }

    private ResultActions register(String name, String email, String password, int expected) throws Exception {
        return mvc.perform(post("/api/auth/register").with(csrf())
                        .contentType(MediaType.APPLICATION_JSON).content(registerJson(name, email, password)))
                .andExpect(status().is(expected));
    }

    /** Переводчик регистрируется сам. */
    private Account translator(String name) throws Exception {
        String email = "t" + SEQ.incrementAndGet() + "@test.local";
        return new Account(id(register(name, email, PASSWORD, 201)), email, PASSWORD);
    }

    /** Редактора создаёт администратор. */
    private Account editor(String name) throws Exception {
        String email = "e" + SEQ.incrementAndGet() + "@test.local";
        long id = id(send(ADMIN, "POST", "/api/users", "{\"name\":\"" + name + "\",\"email\":\"" + email
                + "\",\"password\":\"" + PASSWORD + "\",\"role\":\"EDITOR\"}", 201));
        return new Account(id, email, PASSWORD);
    }

    private long project(Account owner) throws Exception {
        return id(send(owner, "POST", "/api/translation-projects", "{\"name\":\"Проект\",\"targetLanguage\":\"en\"}", 201));
    }

    private long segment(Account owner, long project, String text) throws Exception {
        return id(send(owner, "POST", "/api/source-segments",
                "{\"projectId\":" + project + ",\"sourceText\":\"" + text + "\"}", 201));
    }

    private long translation(Account author, long segment, String text) throws Exception {
        return id(send(author, "POST", "/api/translations", "{\"segmentId\":" + segment + ",\"text\":\"" + text + "\"}", 201));
    }

    private void start(Account owner, long project) throws Exception {
        send(owner, "POST", "/api/translation-projects/" + project + "/start", null, 200)
                .andExpect(jsonPath("$.status").value("IN_PROGRESS"));
    }
}



