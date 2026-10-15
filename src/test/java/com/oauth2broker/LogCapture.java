package com.oauth2broker;

import java.util.List;

import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;

/// Sets a class's logger to a level and collects what it logs; [#close()] restores the logger.
public final class LogCapture implements AutoCloseable {

    private final Logger logger;
    private final Level previous;
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();

    private LogCapture(Class<?> type, Level level) {
        logger = (Logger) LoggerFactory.getLogger(type);
        previous = logger.getLevel();
        logger.setLevel(level);
        appender.start();
        logger.addAppender(appender);
    }

    public static LogCapture debug(Class<?> type) {
        return new LogCapture(type, Level.DEBUG);
    }

    public static LogCapture info(Class<?> type) {
        return new LogCapture(type, Level.INFO);
    }

    /// Formatted messages of the events at DEBUG.
    public List<String> debugMessages() {
        return appender.list.stream()
                .filter(event -> event.getLevel() == Level.DEBUG)
                .map(ILoggingEvent::getFormattedMessage)
                .toList();
    }

    public List<ILoggingEvent> events() {
        return appender.list;
    }

    @Override
    public void close() {
        logger.detachAppender(appender);
        logger.setLevel(previous);
    }
}
