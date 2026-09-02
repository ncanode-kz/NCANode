package kz.ncanode.integration

import kz.ncanode.common.IntegrationSpecification
import kz.ncanode.controller.HomePageController
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.web.servlet.setup.MockMvcBuilders

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class HomePageControllerIntegrationTest extends IntegrationSpecification {

    @Autowired
    HomePageController homePageController

    def setup() {
        mockMvc = MockMvcBuilders.standaloneSetup(homePageController).build()
    }

    def "renders the home page with version and banner substituted"() {
        when:
        def body = mockMvc.perform(get("/"))
            .andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith("text/html"))
            .andReturn().response.contentAsString

        then:
        body != null
        !body.contains('#{VERSION}')
        !body.contains('#{BANNER}')
    }
}
