package pl.artur.zaczek.fitauthapp.rest.model;

import pl.artur.zaczek.fitauthapp.model.Role;

public record AuthorizationDto(String email, Role role) {
}
