import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class Main {

    @Configuration
    @EnableWebSecurity
    public class ConfiguracioSeguretatWeb extends WebSecurityConfigurerAdapter {

        @Autowired
        private ElMeuUserDetailsService userDetailsService;


        public BCryptPasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }


        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                    .authorizeRequests()
                    .antMatchers("/", "/inici").permitAll()
                    .anyRequest().authenticated()
                    .and()
                    .formLogin()
                    .loginPage("/login")
                    .permitAll()
                    .and()
                    .logout()
                    .permitAll();

        }


        public PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }
        @Data
        @NoArgsConstructor
        @AllArgsConstructor
        public class Usuari{
            private String username;
            private String password;
            private String rol; //"USER" o "ADMIN"

            public Usuari(String user, String pwd) {
                username=user;
                password=pwd;
                rol="USER"; //per defecte, tothom és USER
            }
        }

    }
}