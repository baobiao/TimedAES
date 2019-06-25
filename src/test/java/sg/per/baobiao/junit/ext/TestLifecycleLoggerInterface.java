package sg.per.baobiao.junit.ext;

import java.util.logging.Logger;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.TestInstance;

/**
 * Copied from https://junit.org/junit5/docs/current/user-guide/#writing-tests-dependency-injection.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public interface TestLifecycleLoggerInterface
{
    static final Logger logger = Logger.getLogger(TestLifecycleLoggerInterface.class.getName());

    @BeforeAll
    default void beforeAllTests()
    {
        logger.info("Before all tests");
    }

    @AfterAll
    default void afterAllTests()
    {
        logger.info("After all tests");
    }

    @BeforeEach
    default void beforeEachTest(TestInfo testInfo)
    {
        logger.info(() -> String.format("About to execute [%s]", testInfo.getDisplayName()));
    }

    @AfterEach
    default void afterEachTest(TestInfo testInfo)
    {
        logger.info(() -> String.format("Finished executing [%s]", testInfo.getDisplayName()));
    }
}
