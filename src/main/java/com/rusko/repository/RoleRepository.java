package com.rusko.repository;

import com.rusko.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {

  public Role findByRole(String role);
}
