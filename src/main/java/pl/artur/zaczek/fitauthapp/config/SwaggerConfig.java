package pl.artur.zaczek.fitauthapp.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Contact;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@Configuration
@EnableSwagger2
public class SwaggerConfig {
    ApiInfo apiInfo() {
        return new ApiInfoBuilder()
                .title("Fitness Auth API")
                .description("Rest API for fitness authorization and role management app")
                .license("GNU General Public License v3.0")
                .termsOfServiceUrl("")
                .version("0.0.3")
                .contact(new Contact("", "", "ul0255225@edu.uni.lodz.pl"))
                .build();
    }

    @Bean
    public Docket api() {
        return new Docket(DocumentationType.SWAGGER_2)
                .select()
                .apis(RequestHandlerSelectors.basePackage("pl.artur.zaczek.fit.user.app.rest"))
                .paths(PathSelectors.any())
                .build()
                .apiInfo(apiInfo());
    }
}
