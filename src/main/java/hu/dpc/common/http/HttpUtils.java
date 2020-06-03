package hu.dpc.common.http;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URL;
import java.util.Map;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

@Slf4j
@ParametersAreNonnullByDefault
public class HttpUtils {

  @Nonnull
  public static <T extends HttpResponse> T doGET(final Class<T> type, final String query,
      final Map<String, String> headers) throws ResponseStatusException {
    return call(HttpMethod.GET, type, query, headers, null);
  }


  @Nonnull
  public static <T extends HttpResponse> T call(final HttpMethod method, final Class<T> type, final String query,
      final Map<String, String> headers, @CheckForNull final String body) throws ResponseStatusException {
    try {
      final HttpResponse response = HttpHelper.doAPICall(method, new URL(query), headers, body);
      final ObjectMapper mapper = new ObjectMapper();
      final T result = mapper.readValue(response.getHttpRawContent(), type);
      result.setHttpResponseCode(response.getHttpResponseCode());
      result.setHttpRawContent(response.getHttpRawContent());

      return result;
    } catch (final Exception e) {
      log.error("Something went wrong!", e);
      throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Something went wrong!", e);
    }
  }
}
