package io.kestra.plugin.gitguardian.scan;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Location of a secret match in a document. The matched string is never mapped, to keep it out of outputs. */
@Getter
@Setter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class PolicyBreakMatch {
    @Schema(title = "Kind of match", description = "For example `apikey`, `client_id`, `password`, or `host`.")
    @JsonAlias("name")
    private String type;

    @Schema(title = "Start index of the match in the document")
    @JsonAlias({"index_start", "indice_start"})
    private Integer indexStart;

    @Schema(title = "End index of the match in the document")
    @JsonAlias({"index_end", "indice_end"})
    private Integer indexEnd;

    @Schema(title = "Start line of the match")
    @JsonAlias("line_start")
    private Integer lineStart;

    @Schema(title = "End line of the match")
    @JsonAlias("line_end")
    private Integer lineEnd;
}
